# i had to do so much online research and chat and claude and all to get this makefile to work
# i hate makefies

CC 		:= gcc
CFLAGS 	:= -Wall -Wextra -Werror -std=c99
LDLIBS 	:= -lpcap

SRCS    := trace.c checksum.c
OBJS 	:= $(SRCS:.c=.o)
TARGET 	:= trace

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c	
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: test one

test: $(TARGET)
	@set -e; \
	for p in test_files/*.pcap; do \
		echo "== $$p =="; \
		./$(TARGET) "$$p" | diff -u - "$${p%.pcap}.out"; \
	done; \
	echo "All tests passed."

one: $(TARGET)
	@test -n "$(P)" || { echo "Usage: make one P=test_files/file.pcap"; exit 2; }; \
	echo "== $(P) =="; \
	./$(TARGET) "$(P)" | diff -u - "$${P%.pcap}.out"