CXX      = g++
NPCAP_SDK = ../npcap-sdk
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I$(NPCAP_SDK)/Include -I/mingw64/include/pdcurses
LDFLAGS  = -L$(NPCAP_SDK)/Lib/x64 -L/mingw64/lib -lwpcap -lws2_32 -lpdcurses_wincon -lwinmm

TARGET  = pcap_parser
SRCS    = main.cpp parser.cpp flow_tracker.cpp sni.cpp policy.cpp ui.cpp

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
