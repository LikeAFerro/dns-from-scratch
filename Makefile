CC = gcc
CFLAGS = -g -Wall -Wextra -O2

TARGET = dns-from-scratch
SRC = src/dns-from-scratch.c src/assets.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

test: $(TARGET)
	./test.sh

clean:
	rm -f $(TARGET)
