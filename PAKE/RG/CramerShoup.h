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
#include <sstream>

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

public:
	std::string as_string(){
		std::stringstream ss;
		ss << "u1: " << std::hex << u1 << std::endl;
		ss << "u2: " << std::hex << u2 << std::endl;
		ss << "e: " << std::hex << e << std::endl;
		ss << "v: " << std::hex << v << std::endl;
		return ss.str();
	}
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

	Ciphertext encrypt(Botan::BigInt, std::string = ""); // message has to be element from G and the label a string
	Botan::BigInt decrypt(Ciphertext, std::string = "");

	static Botan::BigInt hashIt(Botan::BigInt, Botan::BigInt, Botan::BigInt, std::string = "");
	static Botan::OctetString encodeCiphertext(Ciphertext);
	static Ciphertext decodeCiphertext(Botan::OctetString);
	static void addBigInt(Botan::BigInt, std::vector<Botan::byte>*);
	static void printCiphertext(Ciphertext);

	~CramerShoup(){
		// nothing here yet...
	}

	const KeyPair& getKp() const {
		return kp;
	}

	void setKp(const KeyPair& kp) {
		this->kp = kp;
	}

	const Botan::BigInt& getR() const {
		return r;
	}
};

#endif /* CRAMERSHOUP_H_ */
