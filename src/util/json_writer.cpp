// src/util/json_writer.cpp
#include "btclegacy/util/json_writer.h"
#include <sstream>
#include <iomanip>

namespace btclegacy::util {

void JsonValue::emit_escaped(std::ostringstream& os, const std::string& s) {
    os << '"';
    for (char c : s) {
        switch (c) {
            case '"':  os << "\\\""; break;
            case '\\': os << "\\\\"; break;
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    os << "\\u"
                       << std::hex << std::setfill('0') << std::setw(4)
                       << static_cast<int>(static_cast<unsigned char>(c))
                       << std::dec;
                } else {
                    os << c;
                }
        }
    }
    os << '"';
}

std::string JsonValue::indent_str(int n) {
    return std::string(size_t(n * 2), ' ');
}

std::string JsonValue::to_string(bool pretty, int indent) const {
    std::ostringstream os;
    std::visit([&](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            os << "null";
        } else if constexpr (std::is_same_v<T, bool>) {
            os << (arg ? "true" : "false");
        } else if constexpr (std::is_same_v<T, int64_t>) {
            os << arg;
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            os << arg;
        } else if constexpr (std::is_same_v<T, double>) {
            os << std::setprecision(15) << arg;
        } else if constexpr (std::is_same_v<T, std::string>) {
            emit_escaped(os, arg);
        } else if constexpr (std::is_same_v<T, JsonArray>) {
            if (arg.empty()) { os << "[]"; return; }
            os << "[";
            for (size_t i = 0; i < arg.size(); ++i) {
                if (pretty) os << "\n" << indent_str(indent + 1);
                os << arg[i].to_string(pretty, indent + 1);
                if (i + 1 < arg.size()) os << ",";
            }
            if (pretty) os << "\n" << indent_str(indent);
            os << "]";
        } else if constexpr (std::is_same_v<T, JsonObject>) {
            if (arg.empty()) { os << "{}"; return; }
            os << "{";
            size_t i = 0;
            for (const auto& kv : arg) {
                if (pretty) os << "\n" << indent_str(indent + 1);
                emit_escaped(os, kv.first);
                os << (pretty ? ": " : ":");
                os << kv.second.to_string(pretty, indent + 1);
                if (++i < arg.size()) os << ",";
            }
            if (pretty) os << "\n" << indent_str(indent);
            os << "}";
        }
    }, v_);
    return os.str();
}

} // namespace btclegacy::util
