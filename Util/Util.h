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

#define BILLION 1000000000L

enum ROLE {SERVER = 0, CLIENT = 1};

typedef Botan::OctetString key;
typedef Botan::OctetString message;

struct mk {
	key k;
	message m;
};

struct clonable {
    virtual ~clonable() {}
    virtual clonable* clone() const = 0;
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
	static void splitFinalCombinedMessage(Botan::OctetString m, Botan::OctetString &min, Botan::OctetString &conf);
	static void OctetStringSplit(Botan::OctetString in, Botan::OctetString &first, Botan::OctetString &second, Botan::u32bit sizeOfFirst);

	static void gen_random(char *s, const int len);
};


#endif /* UTIL_H_ */
