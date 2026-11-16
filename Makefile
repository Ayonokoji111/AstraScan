CXX ?= c++
CPPFLAGS += -Iinclude
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -pthread
LDLIBS += -pthread
TLS ?= 1
ifeq ($(TLS),1)
CPPFLAGS += -DASTRA_TLS
LDLIBS += -lssl -lcrypto
endif
SOURCES := src/config.cpp src/scanner.cpp src/report.cpp src/http.cpp
BUILD ?= build
.PHONY: all test clean install
all: $(BUILD)/astrascan
$(BUILD):
	mkdir -p $@
$(BUILD)/astrascan: $(SOURCES) src/main.cpp include/astra/astra.hpp Makefile | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) src/main.cpp $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/unit_tests: $(SOURCES) tests/unit.cpp include/astra/astra.hpp Makefile | $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SOURCES) tests/unit.cpp $(LDFLAGS) $(LDLIBS) -o $@
test: all $(BUILD)/unit_tests
	$(BUILD)/unit_tests
	python3 tests/integration.py $(BUILD)/astrascan
	python3 -m unittest discover -s tests -p 'test_*.py'
PREFIX ?= /usr/local
install: all
	install -Dm755 $(BUILD)/astrascan $(DESTDIR)$(PREFIX)/bin/astrascan
	install -Dm755 tools/astra-diff.py $(DESTDIR)$(PREFIX)/bin/astra-diff
	install -Dm755 tools/astra-policy.py $(DESTDIR)$(PREFIX)/bin/astra-policy
clean:
	rm -rf $(BUILD)
