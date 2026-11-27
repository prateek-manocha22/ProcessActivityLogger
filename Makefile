CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -g
TARGET = build/logger
SRCS = $(wildcard logger/*.c)
OBJS = $(patsubst logger/%.c, build/%.o, $(SRCS))

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

build/%.o: logger/%.c
	mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build

.PHONY: all clean
