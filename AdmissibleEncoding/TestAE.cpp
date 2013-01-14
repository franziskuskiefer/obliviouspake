/*
 * TestAE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "PrimeGroupAE.h"

void testPrimeFactorization(PrimeGroupAE *pae, Botan::AutoSeeded_RNG &rng){
	Botan::BigInt r = Botan::BigInt::random_integer(rng, 2, 1000000);
	std::cout << "n: " << r << "\n";
	std::vector<Botan::BigInt> factorization = pae->primeFactors(r);
	std::cout << "Factorization: ";
	for( std::vector<Botan::BigInt>::const_iterator i = factorization.begin(); i != factorization.end(); ++i)
		std::cout << *i << " ";
	std::cout << "\n";
}

void testGroups(){
	Botan::AutoSeeded_RNG rng;

	std::cout << "modp/ietf/1536\n";
	Botan::DL_Group G("modp/ietf/1536");
	PrimeGroupAE pae(&G);

	std::cout << "modp/ietf/2048\n";
	G = Botan::DL_Group("modp/ietf/1536");
	PrimeGroupAE pae6(&G);

	std::cout << "modp/ietf/3072\n";
	G = Botan::DL_Group("modp/ietf/3072");
	PrimeGroupAE pae2(&G);

	std::cout << "modp/ietf/4096\n";
	G = Botan::DL_Group("modp/ietf/4096");
	PrimeGroupAE pae3(&G);

	std::cout << "modp/ietf/6144\n";
	G = Botan::DL_Group("modp/ietf/6144");
	PrimeGroupAE pae4(&G);

	std::cout << "modp/ietf/8192\n";
	G = Botan::DL_Group("modp/ietf/8192");
	PrimeGroupAE pae5(&G);
}

void encDecTest(Botan::DL_Group *G, Botan::AutoSeeded_RNG *rng, PrimeGroupAE *pae){
	Botan::BigInt r = Botan::BigInt::random_integer(*rng, 2, G->get_p());
	Botan::BigInt in = Botan::power_mod(G->get_g(), r, G->get_p());

	Botan::BigInt encoded = pae->encode(in);
	Botan::BigInt decoded = pae->decode(encoded);

	if (in == decoded)
		std::cout << "Prime Group AE Enc/Dec Test was successful :)\n";
	else
		std::cout << "ERROR on Prime Group AE Enc/Dec Test  :(\n";
}

int main(int argc, char **argv) {
	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	Botan::DL_Group G("modp/ietf/2048");
	Botan::AutoSeeded_RNG rng;

	PrimeGroupAE pae(&G);

//	testPrimeFactorization(&pae, rng);
//	testGroups();

	encDecTest(&G, &rng, &pae);
}
