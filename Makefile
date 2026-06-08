CC = gcc
CFLAGS = -g -Wall -Wextra -O2
# AddressSanitizer flags for memory debugging
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer

TARGET = dns-from-scratch
SRC = src/dns-from-scratch.c src/assets.c
# Convert .c source files into .o object files
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Force a clean environment, then launch a fresh Make session with injected flags
memcheck:
	$(MAKE) clean
	$(MAKE) $(TARGET) CFLAGS="$(CFLAGS) $(ASAN_FLAGS)"
	./test.sh

test: all
	./test.sh

clean:
	rm -f $(TARGET) $(OBJ) test.log

.PHONY: all test clean memcheck
