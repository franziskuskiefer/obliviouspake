/*
 * pake.h
 *
 *  contains all common defines and interface of PAKE protocols
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#ifndef PAKE_H_
#define PAKE_H_

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>

enum ROLE {SERVER = 0, CLIENT = 1};

typedef Botan::OctetString key;
typedef Botan::OctetString message;

struct mk {
	key k;
	message m;
};

/**
 * The overall PAKE class
 */
class Pake {

public:
	virtual void init(std::string, ROLE) = 0;
	virtual mk next(message) = 0;

	/**
	 * Utility function to convert a password string into a BigInt
	 */
	Botan::BigInt pwdToBigInt(std::string pwd){
		const Botan::byte* pwdB = (Botan::byte*)&pwd[0];
		return Botan::BigInt::decode(pwdB, pwd.length(), Botan::BigInt::Binary);
	}

	virtual ~Pake(){}
};

#endif /* PAKE_H_ */
