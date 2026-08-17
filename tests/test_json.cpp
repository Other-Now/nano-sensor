#include "test_util.hpp"

#include "ns/json.hpp"

using ns::JsonWriter;

NS_TEST(json_flat_object) {
    JsonWriter w;
    w.begin_object();
    w.field("a", "x");
    w.field("n", 42);
    w.field("t", true);
    w.end_object();
    CHECK_EQ(w.str(), std::string(R"({"a":"x","n":42,"t":true})"));
}

// The bug this guards against: without an explicit const char* overload, a
// string literal binds to field(key, bool) -- pointer-to-bool is a standard
// conversion, pointer-to-string_view is a user-defined one -- and every literal
// in the codebase silently serialises as `true`.
NS_TEST(json_string_literal_is_not_a_bool) {
    JsonWriter w;
    w.begin_object();
    w.field("k", "literal");
    w.end_object();
    CHECK_EQ(w.str(), std::string(R"({"k":"literal"})"));
}

NS_TEST(json_escaping) {
    CHECK_EQ(ns::json_escape("quote\"back\\slash"), std::string("quote\\\"back\\\\slash"));
    CHECK_EQ(ns::json_escape("tab\there"), std::string("tab\\there"));
    CHECK_EQ(ns::json_escape("nl\n"), std::string("nl\\n"));
    // Control characters must be \u-escaped or the document is invalid JSON.
    CHECK_EQ(ns::json_escape(std::string("\x01")), std::string("\\u0001"));
    // Bytes >= 0x80 pass through: producers hand us UTF-8 already.
    CHECK_EQ(ns::json_escape("caf\xc3\xa9"), std::string("caf\xc3\xa9"));
}

NS_TEST(json_nested_and_arrays) {
    JsonWriter w;
    w.begin_object();
    w.begin_array("xs");
    w.value("a");
    w.value("b");
    w.end_array();
    w.begin_object("inner");
    w.field("z", 1);
    w.end_object();
    w.end_object();
    CHECK_EQ(w.str(), std::string(R"({"xs":["a","b"],"inner":{"z":1}})"));
}

NS_TEST(json_empty_containers) {
    JsonWriter w;
    w.begin_object();
    w.begin_array("empty");
    w.end_array();
    w.field_null("gone");
    w.end_object();
    CHECK_EQ(w.str(), std::string(R"({"empty":[],"gone":null})"));
}

NS_TEST(json_negative_and_wide_integers) {
    JsonWriter w;
    w.begin_object();
    w.field("neg", -17);
    w.field("big", static_cast<std::int64_t>(1786971864208LL));
    w.field("port", static_cast<std::uint16_t>(49664));
    w.end_object();
    CHECK_EQ(w.str(), std::string(R"({"neg":-17,"big":1786971864208,"port":49664})"));
}
