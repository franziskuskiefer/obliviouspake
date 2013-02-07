/*
 * OSpakeTest.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-RGPAKE.h"

void test1(Botan::DL_Group G, std::string pwd, std::vector<std::string> pwds, CramerShoup *cs, std::string ids){
	int c = 3;

	std::vector<std::string> serverPwd;
	serverPwd.push_back(pwd);

	// create RGpake Server & Client instances
	PublicKey pk = cs->getKp().pk;
	ORGpake server(G, ids, pk), client(G, ids, pk);
	server.init(serverPwd, SERVER, c);
	client.init(pwds, CLIENT, c);

	// first message is empty obiously...
	message m0;
	mk s1 = server.next(m0); // c
	mk c1 = client.next(s1.m);
	mk s2 = server.next(c1.m);
	mk c2 = client.next(s2.m);
	std::cout << "Client key: " << c2.k.as_string() << "\n";
	std::cout << "Server key: " << s2.k.as_string() << "\n";
	std::cout << ((c2.k == s2.k) ? "Everything worked fine with O-RG-DDH PAKE :)" : ":( Something went wrong with O-RG-DDH PAKE...")  << "\n";
}


int main(int argc, char **argv) {
	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	std::string pwd = "SecurePassword";
	std::vector<std::string> pwds;
	pwds.push_back("FacebookPassword");
	pwds.push_back("SecurePassword");
	pwds.push_back("GooglePassword");
	Botan::DL_Group G("modp/ietf/2048");

	// generate CRS, i.e. PK of Cramer-Shoup encryption scheme
	CramerShoup cs;
	cs.keyGen(G);

	std::string ids = "Alice and Bob";

	test1(G, pwd, pwds, &cs, ids);
}
