#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ns {

// A deliberately tiny JSON writer.
//
// The agent only ever *emits* JSON -- inventory reports, structured log lines,
// telemetry batches. It never parses any (remote config in stage 5 is the one
// exception, and that arrives signed and schema-fixed). Pulling in a full JSON
// library would buy a parser we don't want and a dependency we'd have to vendor
// onto two platforms.
class JsonWriter {
public:
    explicit JsonWriter(bool pretty = false);

    JsonWriter& begin_object();                      // root, or array element
    JsonWriter& begin_object(std::string_view key);  // member of an object
    JsonWriter& end_object();

    JsonWriter& begin_array(std::string_view key);
    JsonWriter& end_array();

    // The const char* overload is not redundant: without it, a string literal
    // binds to the bool overload (pointer->bool is a standard conversion,
    // pointer->string_view is a user-defined one) and every literal silently
    // serialises as `true`.
    JsonWriter& field(std::string_view key, std::string_view value);
    JsonWriter& field(std::string_view key, const char* value);
    JsonWriter& field(std::string_view key, bool value);
    JsonWriter& field_null(std::string_view key);

    template <class T,
              std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
    JsonWriter& field(std::string_view key, T value) {
        return field_i64(key, static_cast<std::int64_t>(value));
    }

    JsonWriter& value(std::string_view v);  // element of an array

    const std::string& str() const { return out_; }

private:
    JsonWriter& field_i64(std::string_view key, std::int64_t value);
    void separator();
    void newline_indent();
    void write_key(std::string_view key);
    void write_quoted(std::string_view s);

    std::string out_;
    std::vector<int> counts_;  // element count for each currently open container
    bool pretty_;
};

// Escapes a string's *contents* (no surrounding quotes).
std::string json_escape(std::string_view s);

} // namespace ns
