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

void test1(Botan::DL_Group G, std::string pwd, CramerShoup *cs, std::string ids){
	// create Spake Server & Client instances
	PublicKey pk = cs->getKp().pk;
	RG_DDH server(&G, ids, &pk), client(&G, ids, &pk);
	server.init(pwd, SERVER);
	client.init(pwd, CLIENT);

	// first message is empty obiously...
	message m0;
	mk s1 = server.next(m0); // c
	std::cout << "m1: " << s1.m.as_string() << "\n";
	mk c1 = client.next(s1.m);
	std::cout << "m2: " << c1.m.as_string() << "\n";
	mk s2 = server.next(c1.m);
	std::cout << "m3: " << s2.m.as_string() << "\n";
//	mk c2 = client.next(s1.m);
//	std::cout << "Client key: " << c2.k.as_string() << "\n";
//	std::cout << "Server key: " << s2.k.as_string() << "\n";
//	std::cout << ((c2.k == s2.k) ? "Everything worked fine with SPAKE :)" : ":( Something went wrong with SPAKE...")  << "\n\n";
}

int main(int argc, char **argv) {
	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	std::string pwd = "SecurePassword";
	Botan::DL_Group G("modp/ietf/2048");

	// generate CRS, i.e. PK of Cramer-Shoup encryption scheme
	CramerShoup cs;
	cs.keyGen(G);

	std::string ids = "Alice and Bob";

	test1(G, pwd, &cs, ids);
}


