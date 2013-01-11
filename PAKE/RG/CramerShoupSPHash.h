/*
 * CramerShoupSPHash.h
 *
 *  Created on: Jan 10, 2013
 *      Author: franziskus
 */

#ifndef CRAMERSHOUPSPHASH_H_
#define CRAMERSHOUPSPHASH_H_

#include "CramerShoup.h"

struct Key {
	Botan::BigInt a, b, c, d;
};

struct X {
	Ciphertext c;
	Botan::BigInt m;
};

class CramerShoupSPHash {

private:
	Botan::AutoSeeded_RNG rng;
	Key k;
	PublicKey pk;

public:
	CramerShoupSPHash();
	CramerShoupSPHash(Key, PublicKey);

	void keyGen(PublicKey);

	Botan::BigInt project(Ciphertext, std::string = "");
	Botan::BigInt hash(X); // x = (c,m)

	~CramerShoupSPHash(){
		// nothing here yet...
	}
};

#endif /* CRAMERSHOUPSPHASH_H_ */
