/*
 * NaturalNumbersAE.h
 *
 *  Created on: Feb 6, 2013
 *      Author: franziskus
 */

#ifndef NATURALNUMBERSAE_H_
#define NATURALNUMBERSAE_H_

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>

#include <stdio.h>
#include <iostream>

#include "AdmissibleEncoding.h"

class NaturalNumbersAE : public AdmissibleEncoding {

private:
	// member variables for internal state
	Botan::BigInt n;
	Botan::BigInt k;
	Botan::BigInt ell;

public:
	NaturalNumbersAE(){};
	NaturalNumbersAE(Botan::BigInt);
	Botan::BigInt encode(Botan::BigInt);
	Botan::BigInt decode(Botan::BigInt);

	~NaturalNumbersAE(){
		// nothing here yet...
	}

	const Botan::BigInt& getEll() const {
		return ell;
	}
};

#endif /* NATURALNUMBERSAE_H_ */
