# CONFIG_PRINT := 0
# export CONFIG_PRINT

CC := gcc

PLUGIN_DIR=../gcc-plugin
PLUGIN=$(PLUGIN_DIR)/cte.so
LIBRARY_DIR=../libcte
LIBRARY=$(LIBRARY_DIR)/libcte.so
LIBRARY_MINIMAL=$(LIBRARY_DIR)/libcte-minimal.a


# -falign-functions is also enabled in -O2
CFLAGS += -Wall -Wextra -fplugin=$(PLUGIN) -I$(LIBRARY_DIR) -g -ggdb -O3 -falign-functions
LDFLAGS += -L$(LIBRARY_DIR)
LIBS    += -lelf -ldl
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = test repeated empty ssl img

.PHONY: clean always

all: ${PRODUCT}

test: test.o other.o $(LIBRARY)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}

repeated: repeated.o $(LIBRARY)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}

empty: empty.o $(LIBRARY_MINIMAL)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}

ssl: ssl.o  $(LIBRARY_MINIMAL)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS} -lssl -lcrypto


img: img.o  $(LIBRARY_MINIMAL)
	$(CXX) $(LDFLAGS) $^ -o $@ ${LIBS} -ljpeg


$(LIBRARY) $(LIBRARY_MINIMAL): always
	$(MAKE) -C $(LIBRARY_DIR)

$(PLUGIN): always
	$(MAKE) -C $(PLUGIN_DIR)

%.o: %.c $(PLUGIN)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
