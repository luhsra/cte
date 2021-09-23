CXX:= g++
GCCPLUGINS_DIR:= $(shell $(CXX) -print-file-name=plugin)
CXXFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -fno-rtti -gdwarf-2 -Wall -Wextra
SOURCES = $(wildcard *.cc)
OBJECTS = $(patsubst %,%.o,$(basename $(SOURCES)))
PRODUCT = cte.so

.PHONY: clean

$(PRODUCT): $(OBJECTS)
	$(CXX) -shared $(CXXFLAGS) $^ -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(PRODUCT) $(OBJECTS)
