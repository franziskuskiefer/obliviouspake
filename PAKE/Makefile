# Makefile for PAKE tests
CC=g++
CFLAGS=-I. -I./* -Wall -O3 -pthread
LDFLAGS=-lboost_system -lbotan-1.10 
SOURCES=*/*.cpp *.cpp
OUTPUT=pakeTest

all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OUTPUT)

clean:
	rm -f $(OUTPUT)
