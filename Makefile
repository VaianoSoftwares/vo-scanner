EXE = vo_scanner.exe
SOURCES = main.c
OBJS = $(addsuffix .o, $(basename $(notdir $(SOURCES))))

CFLAGS = -std=c17
CFLAGS += -Iinclude
CFLAGS += -ggdb -Wall -Wformat -Wextra
# CFLAGS += -Wpedantic
CFLAGS += -Werror
# CFLAGS += -D_DEBUG_UNAME
# CFLAGS += -O2

LIBS = -Llib
LIBS += -lssl -lcrypto -lws2_32 -lpthread -lgdi32 -lwinmm

##---------------------------------------------------------------------
## PLATFORM SPECIFICS
##---------------------------------------------------------------------

ifeq ($(OS),Windows_NT)
	MACHINE = $(OS) $(PROCESSOR_ARCHITECTURE)

	CC = gcc
	CFLAGS += -O2 
	CFLAGS += -DNO_CONSOLE
	CFLAGS += -IC:/msys64/ucrt64/include 
	# CFLAGS += -DNMIN_COM=3
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		MACHINE = Linux
	else
		$(error Unsupported platform $(UNAME_S))
	endif
	UNAME_M := $(shell uname -m)
	ifeq ($(UNAME_M),x86_64)
		MACHINE += AMD64
	endif
	ifneq ($(filter %86,$(UNAME_M)),)
		MACHINE += IA32
	endif
	ifneq ($(filter arm%,$(UNAME_M)),)
		MACHINE += ARM
	endif

	MACHINE += "(Wine)"

	CC = x86_64-w64-mingw32-gcc
	CFLAGS += -I/usr/x86_64-w64-mingw32/include
	CFLAGS += -DNMIN_COM=33
	LIBS += -L/usr/x86_64-w64-mingw32/lib/openssl
endif

##---------------------------------------------------------------------
## BUILD RULES
##---------------------------------------------------------------------

%.o:%.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(EXE)
	@echo Build complete for $(MACHINE)

$(EXE): $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(EXE) $(OBJS)