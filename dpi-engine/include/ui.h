#pragma once
#include "flow_tracker.h"

// Runs the terminal UI loop.
// Refreshes every 1 second until 'q' is pressed or done == true.
void run_ui(const FlowTracker& tracker, const bool& done);
