// Windows HTTPS/mTLS transport, built on WinHTTP.
//
// WinHTTP rather than a bundled OpenSSL because it is already on every Windows
// host, it uses the OS certificate and cipher policy, and -- the reason that
// matters most for this project's target role -- it honours the machine's proxy
// configuration natively, including PAC scripts and authenticated CONNECT, with
// no code of ours involved.
//
// The one unusual thing here is the send sequence. The body is NOT handed to
// WinHttpSendRequest. Instead the request is opened with a declared content
// length, the handshake completes inside SendRequest, the server certificate is
// pinned-checked, and only then is the body written with WinHttpWriteData. Doing
// it the obvious way -- passing the body to SendRequest -- would push the host's
// full software inventory to the peer BEFORE its identity had been verified.

#include "ns/transport.hpp"

#include "ns/log.hpp"

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <fstream>
#include <string>
#include <vector>

namespace ns {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int need = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), need);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

std::string hex_lower(const unsigned char* p, std::size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out += kHex[(p[i] >> 4) & 0xF];
        out += kHex[p[i] & 0xF];
    }
    return out;
}

std::string normalise_pin(std::string pin) {
    std::string out;
    for (char c : pin) {
        if (c == ':' || c == ' ') continue;
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// SHA-256 over the certificate's DER encoding. CertGetCertificateContextProperty
// with CERT_HASH_PROP_ID would be shorter but yields SHA-1, which is not
// something to pin a security channel to in 2026.
bool cert_sha256(PCCERT_CONTEXT cert, std::string& hex, std::string& error) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        error = "BCryptOpenAlgorithmProvider(SHA256) failed";
        return false;
    }

    unsigned char digest[32];
    const NTSTATUS st = BCryptHash(alg, nullptr, 0, cert->pbCertEncoded,
                                   cert->cbCertEncoded, digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) {
        error = "BCryptHash failed";
        return false;
    }
    hex = hex_lower(digest, sizeof(digest));
    return true;
}

// Loads a PKCS#12 bundle (certificate + private key) for client authentication.
PCCERT_CONTEXT load_client_pfx(const std::string& path, const std::string& password,
                               HCERTSTORE& store, std::string& error) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        error = "cannot open client certificate: " + path;
        return nullptr;
    }
    std::string blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    CRYPT_DATA_BLOB pfx{};
    pfx.cbData = static_cast<DWORD>(blob.size());
    pfx.pbData = reinterpret_cast<BYTE*>(blob.data());

    const std::wstring wpass = widen(password);

    // The flag combination matters and the failure it causes is unhelpful: get
    // it wrong and the import SUCCEEDS, yielding a certificate with no usable
    // private key, and the error only surfaces later as WinHttpSendRequest
    // failing with 12186 (ERROR_WINHTTP_CLIENT_CERT_NO_PRIVATE_KEY).
    //
    // PKCS12_NO_PERSIST_KEY is the flag you WANT here -- it keeps the private key
    // in memory instead of writing it into the user's key store, which is the
    // right hygiene for an agent that loads a certificate on every run. It does
    // not work: Schannel, which WinHTTP hands the certificate to, cannot use an
    // ephemeral in-memory key, and the import succeeds anyway, so the failure
    // only appears later as WinHttpSendRequest error 12186.
    //
    // So the key has to be persisted. The tradeoff is real and is the reason the
    // installer, not the agent, should own certificate provisioning in a
    // production build.
    const DWORD attempts[] = {
        CRYPT_USER_KEYSET | PKCS12_ALWAYS_CNG_KSP,
        CRYPT_USER_KEYSET,
        PKCS12_NO_PERSIST_KEY | PKCS12_ALWAYS_CNG_KSP,  // last resort
    };

    DWORD last_error = 0;
    for (DWORD flags : attempts) {
        store = PFXImportCertStore(&pfx, wpass.c_str(), flags);
        if (store) break;
        last_error = GetLastError();
    }
    if (!store) {
        error = "PFXImportCertStore failed for " + path + ", error " +
                std::to_string(last_error);
        return nullptr;
    }

    // A PKCS#12 bundle usually carries the issuing CA alongside the leaf, so
    // CERT_FIND_ANY is wrong here: it returns whichever certificate the store
    // enumerates first, which is often the CA. Handing WinHTTP a CA certificate
    // with no private key is the OTHER way to get error 12186, and it looks
    // identical to a bad import.
    //
    // The client certificate is the one that owns a private key, so select on
    // that rather than on position.
    PCCERT_CONTEXT cert = nullptr;
    PCCERT_CONTEXT candidate = nullptr;
    while ((candidate = CertEnumCertificatesInStore(store, candidate)) != nullptr) {
        DWORD size = 0;
        if (CertGetCertificateContextProperty(candidate, CERT_KEY_PROV_INFO_PROP_ID,
                                              nullptr, &size) ||
            CertGetCertificateContextProperty(candidate, CERT_KEY_CONTEXT_PROP_ID,
                                              nullptr, &size)) {
            cert = CertDuplicateCertificateContext(candidate);
            CertFreeCertificateContext(candidate);
            break;
        }
    }

    if (!cert) {
        error = "no certificate with an associated private key inside " + path;
        CertCloseStore(store, 0);
        store = nullptr;
        return nullptr;
    }
    return cert;
}

class WinHttpTransport : public Transport {
public:
    WinHttpTransport(Config cfg, ParsedUrl url) : cfg_(std::move(cfg)), url_(std::move(url)) {}

    ~WinHttpTransport() override {
        if (client_cert_) CertFreeCertificateContext(client_cert_);
        if (cert_store_) CertCloseStore(cert_store_, 0);
    }

    bool init(std::string& error) {
        pin_ = normalise_pin(cfg_.server_pin_sha256);
        if (pin_.size() != 64) {
            error = "server pin must be a 64-character hex SHA-256, got " +
                    std::to_string(pin_.size()) + " characters";
            return false;
        }
        if (!cfg_.client_cert_path.empty()) {
            client_cert_ = load_client_pfx(cfg_.client_cert_path, "", cert_store_, error);
            if (!client_cert_) return false;
        }
        return true;
    }

    std::string backend_name() const override { return "winhttp"; }

    Result post(const std::string& body, const std::string& content_type) override {
        Result r;

        // WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY makes WinHTTP follow the machine's
        // proxy configuration, including WPAD and PAC. This is the whole reason
        // for choosing WinHTTP: corporate proxy traversal for free.
        HINTERNET session = WinHttpOpen(L"nano-sensor/0.1",
                                        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) {
            r.error = "WinHttpOpen failed, error " + std::to_string(GetLastError());
            r.retryable = true;
            return r;
        }
        WinHttpSetTimeouts(session, cfg_.timeout_ms, cfg_.timeout_ms, cfg_.timeout_ms,
                           cfg_.timeout_ms);

        HINTERNET connect = WinHttpConnect(session, widen(url_.host).c_str(),
                                           static_cast<INTERNET_PORT>(url_.port), 0);
        if (!connect) {
            r.error = "WinHttpConnect failed, error " + std::to_string(GetLastError());
            r.retryable = true;
            WinHttpCloseHandle(session);
            return r;
        }

        HINTERNET request = WinHttpOpenRequest(
            connect, L"POST", widen(url_.path).c_str(), nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!request) {
            r.error = "WinHttpOpenRequest failed, error " + std::to_string(GetLastError());
            r.retryable = true;
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return r;
        }

        // Chain validation is switched off because the pin replaces it -- see
        // transport.hpp. This is the one place in the codebase where a security
        // check is disabled, and it is only sound because the pin check below is
        // mandatory and happens before any body is written.
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                               SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                               SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &security_flags,
                         sizeof(security_flags));

        if (client_cert_) {
            if (!WinHttpSetOption(request, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                                  const_cast<void*>(static_cast<const void*>(client_cert_)),
                                  sizeof(CERT_CONTEXT))) {
                r.error = "could not attach the client certificate, error " +
                          std::to_string(GetLastError());
                cleanup(request, connect, session);
                return r;
            }
        }

        const std::string headers = "Content-Type: " + content_type;
        const std::wstring wheaders = widen(headers);

        // Declare the length but send no data yet: the handshake happens here,
        // the body does not.
        if (!WinHttpSendRequest(request, wheaders.c_str(),
                                static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0,
                                static_cast<DWORD>(body.size()), 0)) {
            const DWORD err = GetLastError();
            r.error = "WinHttpSendRequest failed, error " + std::to_string(err);
            r.retryable = true;
            cleanup(request, connect, session);
            return r;
        }

        if (!verify_pin(request, r.error)) {
            // Not retryable: a wrong certificate is a configuration or attack
            // condition, and retrying it in a loop would just keep offering the
            // client certificate to whoever is on the other end.
            r.retryable = false;
            cleanup(request, connect, session);
            return r;
        }

        DWORD written = 0;
        if (!body.empty() &&
            !WinHttpWriteData(request, body.data(), static_cast<DWORD>(body.size()),
                              &written)) {
            r.error = "WinHttpWriteData failed, error " + std::to_string(GetLastError());
            r.retryable = true;
            cleanup(request, connect, session);
            return r;
        }

        if (!WinHttpReceiveResponse(request, nullptr)) {
            r.error = "WinHttpReceiveResponse failed, error " + std::to_string(GetLastError());
            r.retryable = true;
            cleanup(request, connect, session);
            return r;
        }

        DWORD status = 0, status_size = sizeof(status);
        WinHttpQueryHeaders(request,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                            WINHTTP_NO_HEADER_INDEX);
        r.http_status = static_cast<int>(status);

        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0) break;
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) break;
            chunk.resize(read);
            r.body += chunk;
        }

        r.ok = (r.http_status >= 200 && r.http_status < 300);
        if (!r.ok) {
            r.error = "cloud returned HTTP " + std::to_string(r.http_status);
            // 5xx and 429 are transient; a 4xx will fail identically forever and
            // must not be retried in a loop.
            r.retryable = (r.http_status >= 500) || (r.http_status == 429);
        }

        cleanup(request, connect, session);
        return r;
    }

private:
    static void cleanup(HINTERNET a, HINTERNET b, HINTERNET c) {
        if (a) WinHttpCloseHandle(a);
        if (b) WinHttpCloseHandle(b);
        if (c) WinHttpCloseHandle(c);
    }

    bool verify_pin(HINTERNET request, std::string& error) {
        PCCERT_CONTEXT server_cert = nullptr;
        DWORD size = sizeof(server_cert);
        if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                                &server_cert, &size) ||
            !server_cert) {
            error = "could not read the server certificate, error " +
                    std::to_string(GetLastError());
            return false;
        }

        std::string actual;
        const bool hashed = cert_sha256(server_cert, actual, error);
        CertFreeCertificateContext(server_cert);
        if (!hashed) return false;

        if (actual != pin_) {
            error = "server certificate pin mismatch: expected " + pin_ + ", got " + actual;
            log_error("server certificate pin mismatch",
                      {{"expected", pin_}, {"actual", actual}});
            return false;
        }
        return true;
    }

    Config cfg_;
    ParsedUrl url_;
    std::string pin_;
    HCERTSTORE cert_store_ = nullptr;
    PCCERT_CONTEXT client_cert_ = nullptr;
};

} // namespace

bool transport_available() { return true; }

std::unique_ptr<Transport> make_transport(const Transport::Config& cfg, std::string& error) {
    ParsedUrl url;
    if (!parse_url(cfg.url, url, error)) return nullptr;

    auto t = std::make_unique<WinHttpTransport>(cfg, url);
    if (!t->init(error)) return nullptr;
    return t;
}

} // namespace ns
