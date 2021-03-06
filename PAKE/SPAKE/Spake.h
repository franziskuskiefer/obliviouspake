/*
 * Spake.h
 *
 *  Created on: Jan 9, 2013
 *      Author: franziskus
 */

#ifndef SPAKE_H_
#define SPAKE_H_

#include "../pake.h"
#include <boost/shared_ptr.hpp>

class Spake : public Pake {

private:
	// member variables for internal state
	Botan::DL_Group G;
	Botan::BigInt M, N, publicKey;
	std::string crs;
	boost::shared_ptr<Botan::DH_PrivateKey> privateKey;
	key k;

public:
	Spake(Botan::DL_Group, Botan::BigInt, Botan::BigInt, std::string);
	void init(std::string, ROLE);
	mk next(message);

	~Spake(){
		// nothing here yet...
	}

	Spake* clone() const {
		return new Spake(*this);
	}
};

#endif /* SPAKE_H_ */
