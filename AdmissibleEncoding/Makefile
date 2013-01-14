# Makefile for Admissible Encoding tests
CC=g++
CFLAGS=-I. -Wall -O3 -pthread
LDFLAGS=-lboost_system -lbotan-1.10 
SOURCES=*.cpp
OUTPUT=aeTest

all: 
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OUTPUT)

clean:
	rm -f $(OUTPUT)
