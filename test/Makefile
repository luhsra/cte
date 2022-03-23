# CONFIG_PRINT := 0
# export CONFIG_PRINT

CC := gcc

LIBRARY_DIR=../libcte
LIBRARY=$(LIBRARY_DIR)/libcte.so
LIBRARY_MINIMAL=$(LIBRARY_DIR)/libcte-minimal.a


# -falign-functions is also enabled in -O2
CFLAGS += -Wall -Wextra -I$(LIBRARY_DIR) -g -ggdb -O3 -falign-functions
LDFLAGS += -L$(LIBRARY_DIR)
LIBS    += -lelf -ldl
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = test test-subset repeated empty ssl img

CTEMETA = ctemeta

.PHONY: clean always

all: ${PRODUCT}

test: test.o other.o $(LIBRARY)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}
	${CTEMETA} $@ $@.cte


test-subset: test-subset.o  $(LIBRARY_MINIMAL)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}
	${CTEMETA} $@ $@.cte

repeated: repeated.o $(LIBRARY)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}

empty: empty.o $(LIBRARY_MINIMAL)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS}
	${CTEMETA} $@ $@.cte


ssl: ssl.o  $(LIBRARY_MINIMAL)
	$(CC) $(LDFLAGS) $^ -o $@ ${LIBS} -lssl -lcrypto
	${CTEMETA} $@ $@.cte


img: img.o  $(LIBRARY_MINIMAL)
	$(CXX) $(LDFLAGS) $^ -o $@ ${LIBS} -ljpeg
	${CTEMETA} $@ $@.cte

$(LIBRARY) $(LIBRARY_MINIMAL): always
	$(MAKE) -C $(LIBRARY_DIR)

clean:
	rm -f $(PRODUCT) $(OBJECTS)
