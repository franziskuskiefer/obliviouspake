/*
 * O-RGPAKE.h
 *
 *  Created on: Jan 31, 2013
 *      Author: franziskus
 */

#ifndef O_RGPAKE_H_
#define O_RGPAKE_H_

// The OPAKE Compiler
#include "ObliviousPAKE.h"

// SPAKE protocol
#include "../PAKE/RG/RG-DDH.h"
// The used Admissible Encoding
#include "../AdmissibleEncoding/PrimeGroupAE.h"

class ORGpake : public OPake {

private:

	Botan::DL_Group G;
	PublicKey pk;

	using OPake::init;
	using OPake::nextServer;
	using OPake::nextClient;
	mk nextServer(message m);
	mk nextClient(message m);

public:
	ORGpake(Botan::DL_Group, std::string, PublicKey);
	void init(std::vector<std::string>, ROLE, int);
	mk next(message);
};


#endif /* O_RGPAKE_H_ */
