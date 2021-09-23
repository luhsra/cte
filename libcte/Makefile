CC := gcc
CCFLAGS += -Wall -Wextra -pedantic -O2
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = libcte.a

.PHONY: clean

$(PRODUCT): $(OBJECTS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CCFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
