/*
 * O-SPAKE.h
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#ifndef O_SPAKE_H_
#define O_SPAKE_H_

#include "ObliviousPAKE.h"
#include "../PAKE/SPAKE/Spake.h"

class OSpake : public OPake {

private:

	Botan::DL_Group G;
	Botan::BigInt M, N;
	std::string crs;

public:
	OSpake(Botan::DL_Group, Botan::BigInt, Botan::BigInt, std::string);
	void init(std::vector<std::string>, ROLE, int);
	mk next(message);

};


#endif /* O_SPAKE_H_ */
