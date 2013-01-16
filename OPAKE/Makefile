# Makefile for O-SPAKE test

all:
	 g++ -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/SPAKE/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/SPAKE/Spake.cpp  OSpakeTest.cpp O-SPAKE.cpp -pthread -lboost_system -lbotan-1.10 -pthread -lboost_system -lgnutls -lgcrypt -Wall -g -o opakeTest

clean:
	rm -rf opakeTest
