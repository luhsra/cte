.SUFFIXES:

CONFIG_PRINT      ?= 1
CONFIG_STAT       ?= 1
CONFIG_THRESHOLD  ?= 1
CONFIG_DEBUG      ?= 0


SOURCES = cte.c cte-asm.S
ifeq ($(CONFIG_PRINT), 1)
SOURCES += cte-printf.c
endif

CC := gcc
CFLAGS += -Wall -Wextra -O2 -ggdb -DCONFIG_PRINT=$(CONFIG_PRINT) -DCONFIG_STAT=$(CONFIG_STAT) -DCONFIG_DEBUG=$(CONFIG_DEBUG) -DCONFIG_THRESHOLD=$(CONFIG_THRESHOLD) -fPIC
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCTS = libcte.a libcte.so libcte-minimal.a
HEADERS = cte.h cte-impl.h ../common/meta.h

.PHONY: clean

all: ${PRODUCTS}

libcte.so: ${OBJECTS}
	${CC} -shared ${OBJECTS} -lelf -ldl -o $@

libcte.a: $(OBJECTS)
	ar rcs $@ $^

libcte-minimal.a: cte-minimal.o cte-asm.o cte-printf.o
	ar rcs $@ $^

%.o: %.c $(HEADERS) $(MAKEFILE_LIST)
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S $(MAKEFILE_LIST)
	$(CC) $(CFLAGS) -c -o $@ $<

cte-minimal.o: cte.c $(HEADERS) $(MAKEFILE_LIST)
	$(CC) $(CFLAGS) -DCONFIG_THRESHOLD=0 -DCONFIG_DEBUG=0 -c -o $@ $<


clean:
	rm -f ${PRODUCTS} $(OBJECTS)

%.so: %.o
