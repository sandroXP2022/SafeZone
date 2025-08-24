CC = g++
CFLAGS = -std=c++17 -O3 -pipe -march=native -mtune=native -fPIC
LDFLAGS = -lcrypto -lncurses
TARGET = safezone
LIB = libsafezone.so
SRC = main.cpp
LIBSRC = safezone.cpp
HDR = safezone.h

all: app

lib: $(LIBSRC) $(HDR)
	$(CC) $(CFLAGS) -shared $(LIBSRC) -o $(LIB) -lcrypto
	mv ./$(LIB) /usr/lib/
	ldconfig

app: lib $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(SRC) -lsafezone $(LDFLAGS) -o $(TARGET)

install: app
	mv ./$(TARGET) /usr/bin/
	mkdir -p /root/.config/safezone
	touch /root/.config/safezone/config

uninstall:
	rm -f /usr/bin/$(TARGET)
	rm -f /usr/lib/$(LIB)
	ldconfig

clean:
	rm -f $(TARGET) $(LIB) *.o

