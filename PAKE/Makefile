# Makefile for PAKE tests
CC=g++
CFLAGS=-I. -I./* -Wall -O3 -pthread
LDFLAGS=-Wl,-as-needed -lboost_system -lbotan-1.10 -lgnutls -lgcrypt 
SOURCES=*/*.cpp *.cpp
UTILSRC=../Util/*.cpp
SPAKESRCS=SpakeTest.cpp SPAKE/Spake.cpp ${UTILSRC}
CSSRCS=RG/CramerShoup.cpp RG/CramerShoupSPHash.cpp CramerShoupTest.cpp ${UTILSRC}
RGDDHSRCS=./RG/*.cpp RGTest.cpp ${UTILSRC}
OUTPUT=pakeTest
SPAKEOUTPUT=spakeTest
CSOUTPUT=csTest
RGDDHOUTPUT=rgTest

all: spake cramershoup rg-ddh-pake
	#$(CC) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $(OUTPUT)

spake:
	$(CC) $(CFLAGS) $(SPAKESRCS) $(LDFLAGS) -o $(SPAKEOUTPUT)

cramershoup:
	$(CC) $(CFLAGS) $(CSSRCS) $(LDFLAGS) -o $(CSOUTPUT)

rg-ddh-pake:
	$(CC) $(CFLAGS) $(RGDDHSRCS) $(LDFLAGS) -o $(RGDDHOUTPUT)

clean:
	rm -f $(OUTPUT) $(SPAKEOUTPUT) $(CSOUTPUT) $(RGDDHOUTPUT)
