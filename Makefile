CC = gcc
CFLAGS = -g -Wall -Wextra -O2
# AddressSanitizer flags for memory debugging
ASAN_FLAGS = -fsanitize=address -fno-omit-frame-pointer

TARGET = dns-from-scratch
SRC = src/dns-from-scratch.c src/assets.c
# Convert .c source files into .o object files (keeps the src/ prefix)
OBJ = $(SRC:.c=.o)

all: $(TARGET)

# Compile .c files into .o files (handles src/ paths perfectly)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files into the final executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Force a clean environment, compile with ASAN, test, and clean up afterwards
memcheck:
	$(MAKE) clean
	$(MAKE) $(TARGET) CFLAGS="$(CFLAGS) $(ASAN_FLAGS)"
	./test.sh
	$(MAKE) clean

test: all
	./test.sh

clean:
	rm -f $(TARGET) $(OBJ) test.log

.PHONY: all test clean memcheck
