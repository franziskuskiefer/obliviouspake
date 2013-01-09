/*
 * SpakeTest.cpp
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#include <iostream>

#include "pake.h"
#include "SPAKE/Spake.h"

void test1(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string session_param, std::string pwd){
	// create Spake Server & Client instances
	Spake server(&G, &M, &N, session_param), client(&G, &M, &N, session_param);
	server.init(pwd, SERVER);
	client.init(pwd, CLIENT);

	// first message is empty obiously...
	message m0;
	mk s1 = server.next(m0);
	mk c1 = client.next(m0);
	mk s2 = server.next(c1.m);
	mk c2 = client.next(s1.m);
	std::cout << "Client key: " << c2.k.as_string() << "\n";
	std::cout << "Server key: " << s2.k.as_string() << "\n";
	std::cout << ((c2.k == s2.k) ? "Everything worked fine with SPAKE :)" : ":( Something went wrong with SPAKE...")  << "\n\n";
}

void test2(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string session_param, std::string pwd){
	// create Spake Server & Client instances
	Spake server(&G, &M, &N, session_param), client(&G, &M, &N, session_param);
	server.init(pwd, SERVER);
	client.init(pwd, CLIENT);

	// first message is empty obiously...
	message m0;
	mk s1 = server.next(m0);
	mk c1 = client.next(s1.m);
	mk s2 = server.next(c1.m);
	std::cout << "Client key: " << c1.k.as_string() << "\n";
	std::cout << "Server key: " << s2.k.as_string() << "\n";
	std::cout << ((c1.k == s2.k) ? "Everything worked fine with SPAKE :)" : ":( Something went wrong with SPAKE...")  << "\n\n";
}

void test3(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string session_param, std::string pwd){
	// create Spake Server & Client instances
	Spake server(&G, &M, &N, session_param), client(&G, &M, &N, session_param);
	server.init(pwd, SERVER);
	client.init(pwd, CLIENT);

	// first message is empty obiously...
	message m0;
	mk c1 = client.next(m0);
	mk s1 = server.next(c1.m);
	mk c2 = client.next(s1.m);
	std::cout << "Client key: " << c2.k.as_string() << "\n";
	std::cout << "Server key: " << s1.k.as_string() << "\n";
	std::cout << ((c2.k == s1.k) ? "Everything worked fine with SPAKE :)" : ":( Something went wrong with SPAKE...")  << "\n\n";
}

int main(int argc, char **argv) {
	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	std::string pwd = "SecurePassword";
	Botan::DL_Group G("modp/ietf/2048");

	// global setup --- variables (M,N)
	Botan::AutoSeeded_RNG rng;
	Botan::BigInt tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt M = power_mod(G.get_g(), tmp, G.get_p());

	tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt N = power_mod(G.get_g(), tmp, G.get_p());

	const std::string session_param = "Alice and Bob's shared session parameter";

	test1(G, M, N, session_param, pwd);
	test2(G, M, N, session_param, pwd);
	test3(G, M, N, session_param, pwd);
}



