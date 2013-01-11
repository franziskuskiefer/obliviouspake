/*
 * CramerShoupTest.cpp
 *
 *  Created on: Jan 10, 2013
 *      Author: franziskus
 */

#include "RG/CramerShoup.h"
#include "RG/CramerShoupSPHash.h"

int main(int argc, char **argv) {
	// init Botan
	Botan::LibraryInitializer init;
	Botan::DL_Group G("modp/ietf/2048");

	// create a random message m
	Botan::AutoSeeded_RNG rng;
	Botan::BigInt tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt m = power_mod(G.get_g(), tmp, G.get_p());

	// init CramerShoup
	CramerShoup cs;
	cs.keyGen(G);

	// encrypt m
	Ciphertext c = cs.encrypt(m, "blablablub");

	// decrypt c
	Botan::BigInt m2 = cs.decrypt(c, "blablablub");

	// check
	if (m2 == m) {
		std::cout << "Successful Enc-Dec Test :)\n";
	} else {
		std::cout << ":( Something went wrong...\n" << "Original: " << m << "\nDecrypted: " << m2 << "\n";
	}

	// init according SPHash
	CramerShoupSPHash hash;
	hash.keyGen(cs.getKp().pk);

	Botan::BigInt s = hash.project(c, "blablablub");
	X x;
	x.c = c;
	x.m = m;
	Botan::BigInt h = hash.hash(x);

	Botan::BigInt r = cs.getR();
	Botan::BigInt checkHash = Botan::power_mod(s, r, G.get_p());

	if (checkHash == h){
		std::cout << "Successful SP-Hash Test :)\n";
	} else {
		std::cout << ":( Something went wrong...\n" << "CheckValue: " << checkHash << "\nHash: " << h << "\n";
	}
}


