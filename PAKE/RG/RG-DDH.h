/*
 * Spake.h
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#ifndef SPAKE_H_
#define SPAKE_H_

#include "../pake.h"
#include "CramerShoup.h"
#include "CramerShoupSPHash.h"
#include <boost/shared_ptr.hpp>

class RG_DDH : public Pake {

private:
	Botan::AutoSeeded_RNG rng;

	// member variables for internal state
	CramerShoup cs;
	CramerShoupSPHash csHash;
	std::string ids;
	key k;

	Ciphertext c1, c2;
	Botan::BigInt s1, s2, sk1, sk2;

	void computeMacandKey(Botan::OctetString&, Botan::OctetString&);
	Botan::BigInt pwdToG();

public:
	RG_DDH(Botan::DL_Group*, std::string, PublicKey* = 0);

	void init(std::string, ROLE);
	mk next(message);

	~RG_DDH(){
		// nothing here yet...
	};

	static void messageDecode(message, Botan::BigInt&, Ciphertext&);
	static void messageEncode(message&, Botan::BigInt, Ciphertext);
};

#endif /* SPAKE_H_ */
