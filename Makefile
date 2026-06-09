.PHONY: all build test check lint analyze trace clean install

BUILD_DIR ?= build
CMAKE_FLAGS ?= -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

all: build

configure:
	cmake -B $(BUILD_DIR) $(CMAKE_FLAGS) -G Ninja

build: configure
	cmake --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure --parallel 4

check: build
	./$(BUILD_DIR)/cpfusa check --dir .

lint: build
	./$(BUILD_DIR)/cpfusa lint --dir .

analyze: build
	./$(BUILD_DIR)/cpfusa analyze --dir .

trace: build
	./$(BUILD_DIR)/cpfusa trace --dir .

report: build
	./$(BUILD_DIR)/cpfusa report --format json --output check-report.json --dir .

clean:
	rm -rf $(BUILD_DIR)

install: build
	cmake --install $(BUILD_DIR) --prefix /usr/local
