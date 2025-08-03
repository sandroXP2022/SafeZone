CC = g++
CFLAGS = -std=c++17 -O3 -pipe -march=native -mtune=native
LDFLAGS = -lcrypto -lncurses
TARGET = safezone
SRC = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) -o $(TARGET)

install: $(TARGET)
	mv ./$(TARGET) /usr/bin/

uninstall:
	rm -f /usr/bin/$(TARGET)

clean:
	rm -f $(TARGET)

