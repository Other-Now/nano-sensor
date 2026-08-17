#include "ns/json.hpp"

#include <array>
#include <cstdio>

namespace ns {

namespace {
constexpr char kHex[] = "0123456789abcdef";
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + s.size() / 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                // Control characters must be escaped; anything >= 0x80 is passed
                // through untouched. Every producer in this codebase hands us
                // UTF-8 already (the Windows backend converts at the WideChar
                // boundary), so we never have to guess an encoding here.
                out += "\\u00";
                out += kHex[(c >> 4) & 0xF];
                out += kHex[c & 0xF];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

JsonWriter::JsonWriter(bool pretty) : pretty_(pretty) {}

void JsonWriter::newline_indent() {
    if (!pretty_ || counts_.empty()) return;
    out_ += '\n';
    out_.append(counts_.size() * 2, ' ');
}

void JsonWriter::separator() {
    if (!counts_.empty()) {
        if (counts_.back() > 0) out_ += ',';
        counts_.back() += 1;
    }
    newline_indent();
}

void JsonWriter::write_quoted(std::string_view s) {
    out_ += '"';
    out_ += json_escape(s);
    out_ += '"';
}

void JsonWriter::write_key(std::string_view key) {
    write_quoted(key);
    out_ += pretty_ ? ": " : ":";
}

JsonWriter& JsonWriter::begin_object() {
    separator();
    out_ += '{';
    counts_.push_back(0);
    return *this;
}

JsonWriter& JsonWriter::begin_object(std::string_view key) {
    separator();
    write_key(key);
    out_ += '{';
    counts_.push_back(0);
    return *this;
}

JsonWriter& JsonWriter::end_object() {
    const int n = counts_.empty() ? 0 : counts_.back();
    if (!counts_.empty()) counts_.pop_back();
    if (pretty_ && n > 0) {
        out_ += '\n';
        out_.append(counts_.size() * 2, ' ');
    }
    out_ += '}';
    return *this;
}

JsonWriter& JsonWriter::begin_array(std::string_view key) {
    separator();
    write_key(key);
    out_ += '[';
    counts_.push_back(0);
    return *this;
}

JsonWriter& JsonWriter::end_array() {
    const int n = counts_.empty() ? 0 : counts_.back();
    if (!counts_.empty()) counts_.pop_back();
    if (pretty_ && n > 0) {
        out_ += '\n';
        out_.append(counts_.size() * 2, ' ');
    }
    out_ += ']';
    return *this;
}

JsonWriter& JsonWriter::field(std::string_view key, std::string_view value) {
    separator();
    write_key(key);
    write_quoted(value);
    return *this;
}

JsonWriter& JsonWriter::field(std::string_view key, const char* value) {
    return field(key, value ? std::string_view(value) : std::string_view(""));
}

JsonWriter& JsonWriter::field(std::string_view key, bool value) {
    separator();
    write_key(key);
    out_ += value ? "true" : "false";
    return *this;
}

JsonWriter& JsonWriter::field_i64(std::string_view key, std::int64_t value) {
    separator();
    write_key(key);
    std::array<char, 24> buf{};
    std::snprintf(buf.data(), buf.size(), "%lld", static_cast<long long>(value));
    out_ += buf.data();
    return *this;
}

JsonWriter& JsonWriter::field_null(std::string_view key) {
    separator();
    write_key(key);
    out_ += "null";
    return *this;
}

JsonWriter& JsonWriter::value(std::string_view v) {
    separator();
    write_quoted(v);
    return *this;
}

} // namespace ns
