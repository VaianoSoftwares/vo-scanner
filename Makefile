# compiler
CC = x86_64-w64-mingw32-gcc

# dirs pathnames
INC_DIR = include /usr/x86_64-w64-mingw32/include
LIB_DIR = lib /usr/x86_64-w64-mingw32/lib/openssl
SRC_DIR = src
BIN_DIR = bin
OBJ_DIR = obj

# exec file name
EXEC_FILENAME = vo-scanner.exe

# compiler flags
INC_FLAG = $(addprefix -I,$(INC_DIR))
CFLAG = $(INC_FLAG) -MMD -MP -g

# linker flags
LIB_FLAG = $(addprefix -L,$(LIB_DIR))
LINK_FLAG_BACK = $(LIB_FLAG) -lssl -lcrypto -lws2_32 -lpthread
LINK_FLAG_FRONT = -Wall -Werror

# src files path
SRCS := $(shell find $(SRC_DIR) -name '*.c')
# obj files path
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
# dep files path
DEPS := $(OBJS:.o=.d)

.PHONY: clean

# usage: make
all: $(BIN_DIR)/$(EXEC_FILENAME)

# create exec file
$(BIN_DIR)/$(EXEC_FILENAME): $(OBJS)
	mkdir -p $(dir $@)
	$(CC) $(LINK_FLAG_FRONT) $(OBJS) -o $@ $(LINK_FLAG_BACK)

# compile src files into obj files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAG) -c $< -o $@

# usage: make clean
clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR) &> /dev/null

-include $(DEPS)