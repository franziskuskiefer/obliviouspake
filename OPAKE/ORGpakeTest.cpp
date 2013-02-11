/*
 * OSpakeTest.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-RGPAKE.h"

void test1(Botan::DL_Group G, std::string pwd, std::vector<std::string> pwds, CramerShoup *cs, std::string ids, int numRep){

	double serverAcc = 0, clientAcc = 0;

	for (int i = 0; i < numRep; ++i) {
		struct timespec start, stop;
		double serverTime = 0, clientTime = 0;

		int c = pwds.size();

		std::vector<std::string> serverPwd;
		serverPwd.push_back(pwd);

		// create RGpake Server & Client instances
		PublicKey pk = cs->getKp().pk;
		ORGpake server(G, ids, pk), client(G, ids, pk);
		server.init(serverPwd, SERVER, c);
		client.init(pwds, CLIENT, c);

		// first message is empty obviously...
		message m0;

		clock_gettime(CLOCK_REALTIME, &start);
		mk s1 = server.next(m0);
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

#ifdef DEBUG
		std::cout << "Client key: " << c2.k.as_string() << "\n";
		std::cout << "Server key: " << s2.k.as_string() << "\n";
		std::cout << ((c2.k == s2.k) ? "Everything worked fine with O-RG-DDH PAKE :)" : ":( Something went wrong with O-RG-DDH PAKE...")  << "\n";
#endif

		clientAcc += clientTime;
		serverAcc += serverTime;
	}

	clientAcc /= numRep;
	serverAcc /= numRep;
	printf("Client next Acc: %lf sec\n", clientAcc);
	printf("Server next Acc: %lf sec\n", serverAcc);
}


int main(int argc, char **argv) {

	if (argc < 3){
		std::cout << "Usage: " << argv[0] << " <numPwds> <numRep>\n";
		exit(1);
	}

	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	const int pwdLength = 16;
	std::vector<std::string> pwds;
	for (int var = 0; var < std::atoi(argv[1]); ++var) {
		char pwd[pwdLength];
		Util::gen_random(pwd, pwdLength);
		pwds.insert(pwds.end(), pwd);
	}
	std::string pwd = pwds[rand()%std::atoi(argv[1])];

	Botan::DL_Group G("modp/ietf/2048");

	// generate CRS, i.e. PK of Cramer-Shoup encryption scheme
	CramerShoup cs;
	cs.keyGen(G);

	std::string ids = "Alice and Bob";

	test1(G, pwd, pwds, &cs, ids, atoi(argv[2]));
}
