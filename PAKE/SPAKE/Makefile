# Makefile for SPAKE
-include config.mk

CC=g++
CFLAGS=-pthread -lboost_system -lbotan-1.10 -Wall -O3
CCFLAGS=-O3 -shared -Wl,-soname,$(LIB_NAME)$(LIB_MAJOR_VERSION) -o $(LIB_NAME)$(LIB_MAJOR_VERSION)$(LIB_MINOR_VERSION)$(LIB_BUILD_VERSION)
LDFLAGS=-lgnutls -lgcrypt
SOURCES=*.cpp
OBJECTS=IHME.o
OUTPUT=spake

all: 
	$(CC) $(SOURCES) $(CFLAGS) -o $(OUTPUT)
	#ldconfig -n .
	#ln -s $(LIB_NAME)$(LIB_MAJOR_VERSION) $(LIB_NAME)

build:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(OUTPUT)
