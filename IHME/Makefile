# Make file for IHME
-include config.mk

CC=g++
CFLAGS=-c -fPIC -Wall -O3
CCFLAGS=-O3 -shared -Wl,-soname,$(LIB_NAME)$(LIB_MAJOR_VERSION) -o $(LIB_NAME)$(LIB_MAJOR_VERSION)$(LIB_MINOR_VERSION)$(LIB_BUILD_VERSION)
LDFLAGS=-lgnutls -lgcrypt
SOURCES=IHME.c
OBJECTS=IHME.o

all: $(OBJECTS)
	$(CC) $(CCFLAGS) $(OBJECTS)
	ldconfig -n .
	ln -s $(LIB_NAME)$(LIB_MAJOR_VERSION) $(LIB_NAME)

build:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS)

clean:
	rm -f *.o libihme.so*
