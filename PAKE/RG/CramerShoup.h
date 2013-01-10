/*
 * CramerShoup.h
 *
 *	CCA2 Secure Cramer Shoup Encryption Scheme
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#ifndef CRAMERSHOUP_H_
#define CRAMERSHOUP_H_

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>

#include <iostream>

struct PublicKey {
	Botan::BigInt c, d, h, g2;
	Botan::DL_Group G;
};

struct SecretKey {
	Botan::BigInt x1, x2, y1, y2, z;
};

struct KeyPair {
	PublicKey pk;
	SecretKey sk;
};

struct Ciphertext {
	Botan::BigInt u1, u2, e, v;
};

class CramerShoup {

private:
	Botan::AutoSeeded_RNG rng;
	KeyPair kp;
	Botan::BigInt r;

public:
	CramerShoup();
	CramerShoup(KeyPair);
	CramerShoup(PublicKey);
	void keyGen(Botan::DL_Group);
	Ciphertext encrypt(Botan::BigInt); // message has to be element from G
	Botan::BigInt decrypt(Ciphertext);
	static Botan::BigInt hashIt(Botan::BigInt, Botan::BigInt, Botan::BigInt);

	~CramerShoup(){
		// nothing here yet...
	}

	const KeyPair& getKp() const {
		return kp;
	}

	const Botan::BigInt& getR() const {
		return r;
	}
};

#endif /* CRAMERSHOUP_H_ */
