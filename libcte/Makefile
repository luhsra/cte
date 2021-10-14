CC := g++
CCFLAGS += -Wall -Wextra -O2 -ggdb
SOURCES = $(wildcard *.cc)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = libcte.a

.PHONY: clean

$(PRODUCT): $(OBJECTS)
	ar rcs $@ $^

%.o: %.cc
	$(CC) $(CCFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
