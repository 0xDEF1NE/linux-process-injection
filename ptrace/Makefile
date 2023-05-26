VERSION        := 0.1.0
LD             := -gcc
CFLAGS         :=  
LDFLAGS        := -static
LDLIBS         :=
BUILD          := ./build
OBJ_DIR        := $(BUILD)/objects
BIN_DIR        := $(BUILD)/bin
TARGET         := injector
INCLUDE        := -Isrc/includes
SRC            :=				  \
	$(wildcard src/*.c)           		    
OBJECTS        := $(SRC:%.c=$(OBJ_DIR)/%.o)
DEPENDENCIES   := $(OBJECTS:.o=.d)

all: build $(BIN_DIR)/$(TARGET)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(LD) $(CFLAGS) $(INCLUDE) -c $< -MMD -o $@

$(BIN_DIR)/$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(LD) $(CFLAGS) -o $(TARGET) $^ $(LDFLAGS) $(LDLIBS)

-include $(DEPENDENCIES)

.PHONY: all build clean debug release info

build:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)

debug: CFLAGS += -DDEBUG -g3
debug: all

release: CFLAGS += -O2
release: all

clean:
	-@rm -rvf $(OBJ_DIR)/*
	-@rm -rvf $(BIN_DIR)/*

info:
	@echo "[*] Application dir: ${BIN_DIR}     "
	@echo "[*] Object dir:      ${OBJ_DIR}     "
	@echo "[*] Sources:         ${SRC}         "
	@echo "[*] Objects:         ${OBJECTS}     "
	@echo "[*] Dependencies:    ${DEPENDENCIES}"