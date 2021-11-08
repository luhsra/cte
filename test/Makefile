CC := gcc
CXX := g++

PLUGIN_DIR=../gcc-plugin
PLUGIN=$(PLUGIN_DIR)/cte.so
LIBRARY_DIR=../libcte
LIBRARY=$(LIBRARY_DIR)/libcte.a

CCFLAGS += -Wall -Wextra -fplugin=$(PLUGIN) -I$(LIBRARY_DIR) -ggdb -O0
LDFLAGS += -L$(LIBRARY_DIR) -lelf
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = test

.PHONY: clean always

$(PRODUCT): $(OBJECTS) $(LIBRARY)
	$(CXX) $(LDFLAGS) $^ -o $@

$(LIBRARY): always
	$(MAKE) -C $(LIBRARY_DIR)

$(PLUGIN): always
	$(MAKE) -C $(PLUGIN_DIR)

%.o: %.c $(PLUGIN)
	$(CC) $(CCFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
