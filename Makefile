.SUFFIXES:

#####################################################################
# Project compilation
#####################################################################

BUILD_DIR=./build
EXEC = $(BUILD_DIR)/x509-parser-verif
LIBS = libs/libsign.a libs/x509-parser.o

include common.mk

all: $(EXEC)

$(BUILD_DIR)/x509-parser-verif: src/main.c $(BUILD_DIR)/x509-parser-verif.o $(BUILD_DIR)/cert-extract.o $(BUILD_DIR)/sig-verif.o $(BUILD_DIR)/rand.o
	$(CC) $(BIN_CFLAGS) $(BIN_LDFLAGS) $^ $(LIBS) -o $@

$(BUILD_DIR)/x509-parser-verif.o: src/x509-parser-verif.c src/x509-parser-verif.h
	@mkdir -p  $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(BUILD_DIR)/cert-extract.o: src/cert-extract.c src/cert-extract.h
	@mkdir -p  $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(BUILD_DIR)/sig-verif.o: src/sig-verif.c src/sig-verif.h
	@mkdir -p  $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

$(BUILD_DIR)/rand.o: src/rand.c src/rand.h
	@mkdir -p  $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c $< -o $@

clean:
	@rm -f $(EXEC)
	@find $(BUILD_DIR) -name '*.o' -exec rm -f '{}' \;
	@find -name '*~'  -exec rm -f '{}' \;

.PHONY: all clean
