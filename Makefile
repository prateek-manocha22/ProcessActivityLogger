CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -g

LOGGER = build/logger
VIEWER = build/viewer

LOGGER_SRCS = $(wildcard logger/*.c)
LOGGER_OBJS = $(patsubst logger/%.c, build/%.o, $(LOGGER_SRCS))

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(patsubst tests/%.c, build/tests/%, $(TEST_SRCS))

all: $(LOGGER) $(VIEWER) $(TEST_BINS)

$(LOGGER): $(LOGGER_OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) -o $(LOGGER) $(LOGGER_OBJS)

build/%.o: logger/%.c
	mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

$(VIEWER): cli/viewer.c
	mkdir -p build
	$(CC) $(CFLAGS) cli/viewer.c -o $(VIEWER)

build/tests/%: tests/%.c
	mkdir -p build/tests
	$(CC) $(CFLAGS) $< -o $@

run: $(LOGGER)
	./$(LOGGER)

serve:
	python3 -m http.server 8000

clean:
	rm -rf build

.PHONY: all run serve clean
