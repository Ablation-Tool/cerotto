CC ?= cc
BUILD_DIR ?= build
TARGET := $(BUILD_DIR)/cerotto

CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_POSIX_C_SOURCE=200809L -Isrc -Ivendor/sqlite -Ivendor/cjson
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += -lm

APP_SOURCES := src/main.c src/db.c src/event.c src/audit.c src/process.c src/util.c src/collect.c src/collector_tsk.c src/timeline.c src/analyze.c
VENDOR_SOURCES := vendor/sqlite/sqlite3.c vendor/cjson/cJSON.c
OBJECTS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(APP_SOURCES) $(VENDOR_SOURCES))
DEPS := $(OBJECTS:.o=.d)

.PHONY: all check clean sanitize

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

$(BUILD_DIR)/src/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/vendor/sqlite/%.o: vendor/sqlite/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -Wno-error -MMD -MP -c $< -o $@

$(BUILD_DIR)/vendor/cjson/%.o: vendor/cjson/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

check: $(TARGET)
	CEROTTO_BIN="$(abspath $(TARGET))" python3 tests/test_cerotto.py

sanitize:
	$(MAKE) BUILD_DIR=build/sanitize CFLAGS="-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" all

clean:
	rm -rf build

-include $(DEPS)
