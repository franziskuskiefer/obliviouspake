# Makefile for O-SPAKE test

all:
	 g++ -O3 -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/SPAKE/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/SPAKE/Spake.cpp  OSpakeTest.cpp O-SPAKE.cpp -pthread -lboost_system -lbotan-1.10 -pthread -lboost_system -lgnutls -lgcrypt -Wall -g -o opakeTest

library: compile
	ar rvs O-SPAKE.a *.o
	rm -f *.o
	
compile:
	g++ -static-libstdc++ -static-libgcc -Wall -g -c -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/SPAKE/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/SPAKE/Spake.cpp  O-SPAKE.cpp O-SPAKE-Wrapper.cpp -pthread -Wl,-Bstatic -lboost_system -lbotan-1.10 -lboost_system -lgnutls  -lgcrypt

clean:
	rm -rf opakeTest
	rm -rf *.o
	rm -f O-SPAKE.a