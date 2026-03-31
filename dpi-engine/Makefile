CXX      = g++
NPCAP_SDK = ../npcap-sdk

CXXFLAGS = -std=c++17 -Wall -Wextra -O2 \
           -I$(NPCAP_SDK)/Include \
           -I/mingw64/include/pdcurses \
           -Iinclude

LDFLAGS  = -L$(NPCAP_SDK)/Lib/x64 \
           -L/mingw64/lib \
           -lwpcap -lws2_32 -lpdcurses_wincon -lwinmm

TARGET = dpi_engine
SRCS   = src/main.cpp \
         src/parser.cpp \
         src/flow_tracker.cpp \
         src/sni.cpp \
         src/policy.cpp \
         src/ui.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Build the test PCAP generator (no libpcap needed)
gen_pcap:
	$(CXX) -std=c++17 -o tools/gen_pcap tools/gen_pcap.cpp

clean:
	rm -f $(TARGET) tools/gen_pcap.exe tools/sample.pcap
