CXX:= g++
GCCPLUGINS_DIR:= $(shell $(CXX) -print-file-name=plugin)
CXXFLAGS += -I$(GCCPLUGINS_DIR)/include -fPIC -fno-rtti -gdwarf-2 -Wall -Wextra -pedantic -std=c++20

.PHONY: all clean

all: cte.so

cte.so: cte.o
	$(CXX) -shared $(CXXFLAGS) $^ -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f cte.so cte.o
