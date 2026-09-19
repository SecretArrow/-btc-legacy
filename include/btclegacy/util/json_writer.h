// btclegacy/util/json_writer.h
#pragma once
//
// Minimal JSON writer — no streaming, no external dependency.
// Output is intentionally simple but valid JSON.
//
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <variant>

namespace btclegacy::util {

class JsonValue;
using JsonObject = std::map<std::string, JsonValue>;
using JsonArray  = std::vector<JsonValue>;
using JsonVal   = std::variant<std::monostate, bool, int64_t, uint64_t, double, std::string, JsonArray, JsonObject>;

class JsonValue {
public:
    JsonValue() : v_(std::monostate{}) {}
    JsonValue(bool b) : v_(b) {}
    JsonValue(int i) : v_(int64_t(i)) {}
    JsonValue(int64_t i) : v_(i) {}
    JsonValue(uint32_t i) : v_(uint64_t(i)) {}
    JsonValue(uint64_t i) : v_(i) {}
    JsonValue(double d) : v_(d) {}
    JsonValue(const char* s) : v_(std::string(s)) {}
    JsonValue(std::string s) : v_(std::move(s)) {}
    JsonValue(JsonArray a) : v_(std::move(a)) {}
    JsonValue(JsonObject o) : v_(std::move(o)) {}

    static JsonValue null() { return JsonValue(); }

    std::string to_string(bool pretty = true, int indent = 0) const;

private:
    JsonVal v_;
    static void emit_escaped(std::ostringstream& os, const std::string& s);
    static std::string indent_str(int n);
};

} // namespace btclegacy::util
