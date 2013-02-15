/*
 * SpakeTest.cpp
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#include <iostream>

#include "pake.h"
#include "RG/CramerShoup.h"
#include "RG/CramerShoupSPHash.h"
#include "RG/RG-DDH.h"

void test1(Botan::DL_Group G, std::string pwd, CramerShoup *cs, std::string ids, int numRep){

	double serverAcc = 0, clientAcc = 0;
	bool error = false;

	for (int i = 0; i < numRep; ++i) {
		struct timespec start, stop;
		double serverTime = 0, clientTime = 0;
		// create RGpake Server & Client instances
		PublicKey pk = cs->getKp().pk;

		RG_DDH server(G, ids, pk);
		clock_gettime(CLOCK_REALTIME, &start);
		server.init(pwd, SERVER);
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		RG_DDH client(G, ids, pk);
		clock_gettime(CLOCK_REALTIME, &start);
		client.init(pwd, CLIENT);
		clock_gettime(CLOCK_REALTIME, &stop);
		clientTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		// first message is empty obiously...
		message m0;
		clock_gettime(CLOCK_REALTIME, &start);
		mk s1 = server.next(m0); // c
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk c1 = client.next(s1.m);
		clock_gettime(CLOCK_REALTIME, &stop);
		clientTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk s2 = server.next(c1.m);
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk c2 = client.next(s2.m);
		clock_gettime(CLOCK_REALTIME, &stop);
		clientTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		if (c2.k != s2.k) {
			error = true;
			std::cout << "Client key: " << c2.k.as_string() << "\n";
			std::cout << "Server key: " << s2.k.as_string() << "\n";
			break;
		}

#ifdef DEBUG
		std::cout << "Client key: " << c2.k.as_string() << "\n";
		std::cout << "Server key: " << s2.k.as_string() << "\n";
		std::cout << ((c2.k == s2.k) ? "Everything worked fine with RG-DDH PAKE :)" : ":( Something went wrong with RG-DDH PAKE...")  << "\n";
#endif
		clientAcc += clientTime;
		serverAcc += serverTime;
	}

	if(error)
		printf("An error occurred! --- everything after this is wrong!\n");

	clientAcc /= numRep;
	serverAcc /= numRep;
	printf("Client next Acc: %lf sec\n", clientAcc);
	printf("Server next Acc: %lf sec\n", serverAcc);
}

int main(int argc, char **argv) {

	if (argc < 2){
		std::cout << "Usage: " << argv[0] << " <numRep>\n";
		exit(1);
	}

	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	int pwdLength = 16;
	char pwd[pwdLength];
	Util::gen_random(pwd, pwdLength);
	Botan::DL_Group G("modp/ietf/2048");

	// generate CRS, i.e. PK of Cramer-Shoup encryption scheme
	CramerShoup cs;
	cs.keyGen(G);

	std::string ids = "Alice and Bob";

	test1(G, pwd, &cs, ids, std::atoi(argv[1]));
}



