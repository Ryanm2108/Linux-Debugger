# compiler
CXX = g++

# compile flags
CXXFLAGS = -std=c++17 -g -Wall -Wextra

# libraries to link
LDFLAGS = -ldwarf -lopcodes -lbfd -liberty -lz -ldl

# source files
SRC = debugger.cpp breakpoint.cpp DWARF_parser.cpp

# output binary
BIN = debugger

all:
	$(CXX) $(CXXFLAGS) -o $(BIN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(BIN)
