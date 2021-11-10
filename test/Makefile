CC := gcc

PLUGIN_DIR=../gcc-plugin
PLUGIN=$(PLUGIN_DIR)/cte.so
LIBRARY_DIR=../libcte
LIBRARY=$(LIBRARY_DIR)/libcte.a

# -falign-functions is also enabled in -O2
CFLAGS += -Wall -Wextra -fplugin=$(PLUGIN) -I$(LIBRARY_DIR) -ggdb -O0 -falign-functions
LDFLAGS += -L$(LIBRARY_DIR)
LIBS    += -lelf
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = test

.PHONY: clean always

$(PRODUCT): $(OBJECTS) $(LIBRARY)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}

$(LIBRARY): always
	$(MAKE) -C $(LIBRARY_DIR)

$(PLUGIN): always
	$(MAKE) -C $(PLUGIN_DIR)

%.o: %.c $(PLUGIN)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
