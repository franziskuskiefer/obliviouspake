/*
 * OSpakeTest.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"

void test1(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string session_param, std::string pwd, std::vector<std::string> pwds, int numRep){

	double serverAcc = 0, clientAcc = 0;
	bool error = false;

	for (int i = 0; i < numRep; ++i) {
		struct timespec start, stop;
		double serverTime = 0, clientTime = 0;

		// create Spake Server & Client instances
		int c = pwds.size();
		std::vector<std::string> serverPwd;
		serverPwd.push_back(pwd);

		OSpake server(G, M, N, session_param);
		clock_gettime(CLOCK_REALTIME, &start);
		server.init(serverPwd, SERVER, c);
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		OSpake client(G, M, N, session_param);
		clock_gettime(CLOCK_REALTIME, &start);
		client.init(pwds, CLIENT, c);
		clock_gettime(CLOCK_REALTIME, &stop);
		clientTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		// first message is empty obiously...
		message m0;
		clock_gettime(CLOCK_REALTIME, &start);
		mk s1 = server.next(m0);
#ifdef DEBUG
			std::cout << "s1: " << s1.m.as_string() << "\n";
#endif
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk c1 = client.next(s1.m);
#ifdef DEBUG
		std::cout << "c1: " << c1.m.as_string() << "\n";
#endif
		clock_gettime(CLOCK_REALTIME, &stop);
		clientTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk s2 = server.next(c1.m);
#ifdef DEBUG
		std::cout << "s2: " << s2.m.as_string() << "\n";
#endif
		clock_gettime(CLOCK_REALTIME, &stop);
		serverTime += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

		clock_gettime(CLOCK_REALTIME, &start);
		mk c2 = client.next(s2.m);
#ifdef DEBUG
		std::cout << "c2: " << c2.m.as_string() << "\n";
#endif
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
			std::cout << ((c2.k == s2.k) ? "Everything worked fine with SPAKE :)" : ":( Something went wrong with SPAKE...")  << "\n\n";
			printf("Client next: %lf sec\n", clientTime);
			printf("Server next: %lf sec\n", serverTime);
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

	// global setup --- variables (M,N)
	Botan::AutoSeeded_RNG rng;
	Botan::BigInt tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt M = power_mod(G.get_g(), tmp, G.get_p());

	tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt N = power_mod(G.get_g(), tmp, G.get_p());

	const std::string session_param = "Alice and Bob's shared session parameter";

	test1(G, M, N, session_param, pwd, pwds, std::atoi(argv[2]));
}
