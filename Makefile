CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -g
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS = -lpcap

TARGET = wireview
TARGET_SAN = wireview_san
SRC = wireview.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

sanitize: $(SRC)
	$(CXX) $(CXXFLAGS) $(SANFLAGS) -o $(TARGET_SAN) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_SAN) *.o
