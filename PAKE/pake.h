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

#include "../Util/Util.h"

/**
 * The overall PAKE class
 */
class Pake {

protected:

	ROLE r;
	Botan::BigInt pwd;

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

	ROLE getR() const {
		return r;
	}

	const Botan::BigInt& getPwd() const {
		return pwd;
	}
};

#endif /* PAKE_H_ */
