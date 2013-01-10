# Makefile for PAKE tests
CC=g++
CFLAGS=-I. -I./* -Wall -O3 -pthread
LDFLAGS=-lboost_system -lbotan-1.10 
SOURCES=*/*.cpp *.cpp
SPAKESRCS=SpakeTest.cpp SPAKE/Spake.cpp
CSSRCS=RG/CramerShoup.cpp RG/CramerShoupSPHash.cpp CramerShoupTest.cpp
OUTPUT=pakeTest
SPAKEOUTPUT=spakeTest
CSOUTPUT=csTest

all:
	$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OUTPUT)

spake:
	$(CC) $(CFLAGS) $(SPAKESRCS) $(LDFLAGS) -o $(SPAKEOUTPUT)

cramershoup:
	$(CC) $(CFLAGS) $(CSSRCS) $(LDFLAGS) -o $(CSOUTPUT)

clean:
	rm -f $(OUTPUT) $(SPAKEOUTPUT) $(CSOUTPUT)
