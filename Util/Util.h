/*
 * Util.h
 *
 *  Created on: Jan 16, 2013
 *      Author: franziskus
 */

#ifndef UTIL_H_
#define UTIL_H_

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>

#include <iostream>

#include <math.h>

#include "../IHME/IHME.h"

enum ROLE {SERVER = 0, CLIENT = 1};

typedef Botan::OctetString key;
typedef Botan::OctetString message;

struct mk {
	key k;
	message m;
};

class Util {

private:

public:
	static void BigIntToMpi(gcry_mpi_t *, Botan::BigInt);
	static Botan::BigInt MpiToBigInt(gcry_mpi_t);
	static Botan::BigInt pwdToBigInt(std::string);
	static void print_mpi (const char *name, gcry_mpi_t a);

	static Botan::OctetString MpiToOctetString(gcry_mpi_t in);

	static void addOctetStringToVector(Botan::OctetString toAdd, std::vector<Botan::byte> *vec, bool addLength);
	static void OctetStringConcat(Botan::OctetString &first, Botan::OctetString second, bool addLength);
};


#endif /* UTIL_H_ */
