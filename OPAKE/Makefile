# Makefile for O-SPAKE test

all: ospake orgpake

ospake:
	 g++ -O3 -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/SPAKE/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/NaturalNumbersAE.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/SPAKE/Spake.cpp ObliviousPAKE.cpp  OSpakeTest.cpp O-SPAKE.cpp -pthread -lboost_system -lbotan-1.10 -pthread -lboost_system -lgnutls -lgcrypt -Wall -g -o ospakeTest

orgpake:
	g++ -O3 -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/RG/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/NaturalNumbersAE.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/RG/*.cpp ObliviousPAKE.cpp  ORGpakeTest.cpp O-RGPAKE.cpp -pthread -lboost_system -lbotan-1.10 -pthread -lboost_system -lgnutls -lgcrypt -Wall -g -o orgpakeTest

library: compile
	ar rvs O-SPAKE.a *.o
	rm -f *.o
	
compile:
	g++ -static-libstdc++ -static-libgcc -Wall -g -c -I ../IHME/ -I ../AdmissibleEncoding/ -I ../PAKE/ -I ../PAKE/SPAKE/ -I ../Util/ ../Util/Util.cpp ../AdmissibleEncoding/PrimeGroupAE.cpp ../IHME/IHME.c ../PAKE/SPAKE/Spake.cpp  O-SPAKE.cpp O-SPAKE-Wrapper.cpp -pthread -Wl,-Bstatic -lboost_system -lbotan-1.10 -lboost_system -lgnutls  -lgcrypt

clean:
	rm -rf ospakeTest orgpakeTest
	rm -rf *.o
	rm -f O-SPAKE.a