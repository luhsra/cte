.SUFFIXES:

CONFIG_PRINT ?= 1
CONFIG_STAT  ?= 1

SOURCES = cte.c
ifeq ($(CONFIG_PRINT), 1)
SOURCES += cte-printf.c
endif

CC := gcc
CFLAGS += -Wall -Wextra -O2 -ggdb -DCONFIG_PRINT=$(CONFIG_PRINT) -DCONFIG_STAT=$(CONFIG_STAT) -fPIC
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCTS = libcte.a libcte.so

.PHONY: clean

all: ${PRODUCTS}

libcte.so: ${OBJECTS}
	${CC} -shared ${OBJECTS} -lelf -ldl -o $@

libcte.a: $(OBJECTS)
	ar rcs $@ $^

.SECONDEXPANSION:
%.o: %.c $$*.h cte-impl.h $(MAKEFILE_LIST)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f ${PRODUCTS} $(OBJECTS)

%.so: %.o
