#pragma once
#include <string>
#include <cstdint>

// Evaluates policy rules and returns the action for a flow.
std::string evaluate_policy(const std::string& app_type,
                             const std::string& domain);

// Applies rate limiting on top of existing policy.
// THROTTLE overrides ALLOW/LOG but not BLOCK.
std::string apply_rate_limit(const std::string& current_action,
                              uint64_t total_bytes,
                              uint64_t byte_threshold = 100);
