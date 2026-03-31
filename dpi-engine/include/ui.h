#pragma once
#include "flow_tracker.h"
#include <atomic>

// Runs the terminal UI loop.
// Refreshes every 1 second until 'q' is pressed or done == true.
// Sets stop = true when user presses 'q' (signals live capture to stop).
void run_ui(const FlowTracker& tracker,
            const std::atomic<bool>& done,
            std::atomic<bool>& stop);
