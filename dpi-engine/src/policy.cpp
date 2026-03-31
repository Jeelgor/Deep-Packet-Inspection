#include "policy.h"

std::string evaluate_policy(const std::string& app_type,
                             const std::string& domain) {
    // Domain-based rules (checked first — highest priority)
    if (domain == "youtube.com")  return "BLOCK";

    // App-type rules
    if (app_type == "DNS")        return "ALLOW";
    if (app_type == "HTTP")       return "LOG";

    return "ALLOW";
}

std::string apply_rate_limit(const std::string& current_action,
                              uint64_t total_bytes,
                              uint64_t byte_threshold) {
    // BLOCK is final — rate limiting cannot override it
    if (current_action == "BLOCK") return current_action;

    if (total_bytes > byte_threshold) return "THROTTLE";

    return current_action;
}