/*
 * PrimeGroupAE.h
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#ifndef PRIMEGROUPAE_H_
#define PRIMEGROUPAE_H_

#include "NaturalNumbersAE.h"

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>

#include <stdio.h>
#include <iostream>

#include "AdmissibleEncoding.h"

// Structure to store necessary parameters of Z*_p
struct z_p_star {
	Botan::BigInt p;
	Botan::BigInt a;
	Botan::BigInt g;
};

class PrimeGroupAE :public AdmissibleEncoding {

private:
	Botan::AutoSeeded_RNG rng;

	// member variables for internal state
	Botan::DL_Group G;
	z_p_star Z;
	NaturalNumbersAE nae;

	z_p_star generate_Z();

public:
	PrimeGroupAE(Botan::DL_Group*);
	Botan::BigInt encode(Botan::BigInt);
	Botan::BigInt decode(Botan::BigInt);
	std::vector<Botan::BigInt> primeFactors(Botan::BigInt); // XXX: make private again

	~PrimeGroupAE(){
		// nothing here yet...
	}

	const z_p_star& getZ() const {
		return Z;
	}

	const NaturalNumbersAE& getNae() const {
		return nae;
	}
};


#endif /* PRIMEGROUPAE_H_ */
