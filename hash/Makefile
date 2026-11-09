CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2

TARGET = hash
SOURCE = hash.cpp

CRYPTOPP_PREFIX := $(shell brew --prefix cryptopp 2>/dev/null)
CPPFLAGS := $(if $(CRYPTOPP_PREFIX),-I$(CRYPTOPP_PREFIX)/include)
LDFLAGS := $(if $(CRYPTOPP_PREFIX),-L$(CRYPTOPP_PREFIX)/lib)
LDLIBS = -lcryptopp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCE) $(LDFLAGS) $(LDLIBS) -o $(TARGET)

clean:
	rm -f $(TARGET) *.o
