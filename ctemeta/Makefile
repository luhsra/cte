CXX := g++
CXXFLAGS += -Wall -Wextra -O2
SOURCES = ctemeta.cc elf.cc code.cc cgraph.cc util.cc dump.cc
HEADERS = ctemeta.hh util.hh ../common/meta.h
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCTS = ctemeta

ZYDIS_SRC = zydis
ZYDIS_BUILD = zydis/build
ZYDIS_DIST = zydis-dist
CXXFLAGS += -I$(ZYDIS_DIST)/include
LDFLAGS += -L$(ZYDIS_DIST)/lib -L$(ZYDIS_DIST)/lib64

.PHONY: all clean

all: ${PRODUCTS}

ctemeta: $(ZYDIS_DIST) ${OBJECTS}
	${CXX} $(LDFLAGS) ${OBJECTS} -lelf -lZydis -o $@

%.o: %.cc $(ZYDIS_DIST) $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(ZYDIS_DIST):
	cmake ZYDIS_BUILD_TOOLS \
		-DZYDIS_BUILD_TOOLS=OFF -DZYDIS_BUILD_EXAMPLES=OFF \
		-DCMAKE_INSTALL_PREFIX:PATH="$(PWD)/$(ZYDIS_DIST)" \
		-S $(ZYDIS_SRC) -B $(ZYDIS_BUILD)
	make -C $(ZYDIS_BUILD) install
	make -C $(ZYDIS_BUILD)/zycore install

clean:
	rm -f ${PRODUCTS} $(OBJECTS)
	rm -rf $(ZYDIS_BUILD) $(ZYDIS_DIST)
