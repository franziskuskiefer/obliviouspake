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
class Pake : public clonable {

protected:

	ROLE r;
	Botan::BigInt pwd;

public:
	virtual void init(std::string, ROLE) = 0;
	virtual mk next(message) = 0;

	virtual ~Pake(){}

	ROLE getR() const {
		return r;
	}

	const Botan::BigInt& getPwd() const {
		return pwd;
	}

	virtual Pake* clone() const = 0;
};

#endif /* PAKE_H_ */
