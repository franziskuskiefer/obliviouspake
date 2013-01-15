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

#include <math.h>

class OSpake : public OPake {

private:

	Botan::DL_Group G;
	Botan::BigInt M, N;
	std::string crs;

	Botan::BigInt ihmeDecode(message);
	gcry_mpi_t* MessageToS(Botan::OctetString, int);
	Botan::BigInt MpiToBigInt(gcry_mpi_t);
	void addElement(struct point*, int*, Botan::BigInt, Botan::BigInt);
	Botan::OctetString encodeS(gcry_mpi_t*);
	void addOctetString(Botan::OctetString, std::vector<Botan::byte>*);
	void keyGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *);
	void confGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *);

public:
	OSpake(Botan::DL_Group, Botan::BigInt, Botan::BigInt, std::string);
	void init(std::vector<std::string>, ROLE, int);
	mk next(message);

};


#endif /* O_SPAKE_H_ */
