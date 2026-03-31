#include "ui.h"
#include "flow_key.h"

// PDCurses: define PDC_WIDE + PDC_FORCE_UTF8 to match the MinGW lib's u64 ABI
#define PDC_WIDE
#define PDC_FORCE_UTF8
#include <pdcurses/curses.h>
#include <string>
#include <thread>
#include <chrono>

// Column widths
static constexpr int W_IP     = 18;
static constexpr int W_PORT   =  7;
static constexpr int W_PROTO  =  6;
static constexpr int W_TYPE   =  7;
static constexpr int W_DOMAIN = 20;
static constexpr int W_ACTION = 10;
static constexpr int W_PKTS   =  8;
static constexpr int W_BYTES  = 10;

static const char* proto_label(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        default:             return "OTHER";
    }
}

// Print a fixed-width cell, truncating if needed.
static void print_cell(const std::string& val, int width) {
    std::string s = val.substr(0, width - 1);
    printw("%-*s", width, s.c_str());
}

static void draw_header() {
    attron(A_BOLD | A_REVERSE);
    printw(" %-*s%-*s%-*s%-*s%-*s%-*s%-*s%-*s\n",
        W_IP + W_PORT, "Source",
        W_IP + W_PORT, "Destination",
        W_PROTO,  "Proto",
        W_TYPE,   "Type",
        W_DOMAIN, "Domain",
        W_ACTION, "Action",
        W_PKTS,   "Packets",
        W_BYTES,  "Bytes");
    attroff(A_BOLD | A_REVERSE);
}

static void draw_flows(const FlowTracker& tracker) {
    auto& flows = tracker.flows();
    for (const auto& [key, data] : flows) {
        // Determine client/server side (server has known port)
        bool src_is_server = (key.src_port == 53 || key.src_port == 80 || key.src_port == 443)
                           && (key.dst_port != 53 && key.dst_port != 80 && key.dst_port != 443);

        const std::string& cip  = src_is_server ? key.dst_ip   : key.src_ip;
        uint16_t           cprt = src_is_server ? key.dst_port : key.src_port;
        const std::string& sip  = src_is_server ? key.src_ip   : key.dst_ip;
        uint16_t           sprt = src_is_server ? key.src_port : key.dst_port;

        std::string src = cip + ":" + std::to_string(cprt);
        std::string dst = sip + ":" + std::to_string(sprt);

        // Color by action
        if      (data.action == "BLOCK")    attron(COLOR_PAIR(1));
        else if (data.action == "THROTTLE") attron(COLOR_PAIR(2));
        else if (data.action == "LOG")      attron(COLOR_PAIR(3));
        else                                attron(COLOR_PAIR(4));

        print_cell(src,                       W_IP + W_PORT);
        print_cell(dst,                       W_IP + W_PORT);
        print_cell(proto_label(key.protocol), W_PROTO);
        print_cell(data.app_type,             W_TYPE);
        print_cell(data.domain.empty() ? "-" : data.domain, W_DOMAIN);
        print_cell(data.action,               W_ACTION);
        printw("%-*lu", W_PKTS,  data.packet_count);
        printw("%-*lu\n", W_BYTES, data.total_bytes);

        attroff(COLOR_PAIR(1));
        attroff(COLOR_PAIR(2));
        attroff(COLOR_PAIR(3));
        attroff(COLOR_PAIR(4));
    }
}

void run_ui(const FlowTracker& tracker, const bool& done) {
    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);  // non-blocking getch
    curs_set(0);            // hide cursor

    if (has_colors()) {
        start_color();
        init_pair(1, COLOR_RED,     COLOR_BLACK); // BLOCK
        init_pair(2, COLOR_YELLOW,  COLOR_BLACK); // THROTTLE
        init_pair(3, COLOR_CYAN,    COLOR_BLACK); // LOG
        init_pair(4, COLOR_GREEN,   COLOR_BLACK); // ALLOW
    }

    while (true) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;
        if (done) {
            // render one final time then exit
            erase();
            attron(A_BOLD);
            mvprintw(0, 0, "  DPI Flow Monitor  [Processing complete - press q to exit]");
            attroff(A_BOLD);
            move(3, 0);
            draw_header();
            draw_flows(tracker);
            refresh();
            // wait for q
            nodelay(stdscr, FALSE);
            while (getch() != 'q') {}
            break;
        }

        erase(); // flicker-free clear

        // Title
        attron(A_BOLD);
        mvprintw(0, 0, "  DPI Flow Monitor");
        attroff(A_BOLD);
        mvprintw(1, 0, "  Press 'q' to quit\n\n");

        move(3, 0);
        draw_header();
        draw_flows(tracker);

        refresh();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    endwin();
}
