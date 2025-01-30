CC = x86_64-w64-mingw32-gcc

EXE = vo_scanner.exe
SOURCES = main.c
OBJS = $(addsuffix .o, $(basename $(notdir $(SOURCES))))

INC_PATHS = include /usr/x86_64-w64-mingw32/include
LIB_PATHS = lib /usr/x86_64-w64-mingw32/lib/openssl

INC_FLAGS = $(addprefix -I,$(INC_PATHS))
LIB_FLAGS = $(addprefix -L,$(LIB_PATHS))

CFLAGS = -std=c17
CFLAGS += $(INC_FLAGS)
CFLAGS += -g -Wall -Wformat -Wextra
# CFLAGS += -Wpedantic
CFLAGS += -Werror
CFLAGS += -DNMIN_COM=33
CFLAGS += -D_DEBUG_UNAME
# CFLAGS += -O2

LIBS = $(LIB_FLAGS)
LIBS += -lssl -lcrypto -lws2_32 -lpthread -lgdi32 -lwinmm

##---------------------------------------------------------------------
## BUILD RULES
##---------------------------------------------------------------------

%.o:%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(EXE)
	@echo Build complete for MinGW

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(EXE) $(OBJS)