/*
 * O-SPAKE.h
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#ifndef O_SPAKE_H_
#define O_SPAKE_H_

// The OPAKE Compiler
#include "ObliviousPAKE.h"

// SPAKE protocol
#include "../PAKE/SPAKE/Spake.h"
// The used Admissible Encoding
#include "../AdmissibleEncoding/PrimeGroupAE.h"

class OSpake : public OPake {

private:

	Botan::DL_Group G;
	Botan::BigInt M, N;
	std::string crs;

	using OPake::nextServer;
	using OPake::init;
	mk nextServer(message m);
	mk nextClient(message m);

public:
	OSpake(Botan::DL_Group, Botan::BigInt, Botan::BigInt, std::string);
	void init(std::vector<std::string>, ROLE, int);
	mk next(message);
};

#endif /* O_SPAKE_H_ */
