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
	static Botan::BigInt ihmeDecode(message,Botan::DL_Group, int, Botan::BigInt);
	static gcry_mpi_t* MessageToS(Botan::OctetString, int);
	static Botan::BigInt MpiToBigInt(gcry_mpi_t);
	static void addElement(struct point*, int*, Botan::BigInt, Botan::BigInt);
	static Botan::OctetString encodeS(gcry_mpi_t*, int);
	static void addOctetString(Botan::OctetString, std::vector<Botan::byte>*);
	static void keyGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *, std::vector<Botan::byte>);
	static void confGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *, std::vector<Botan::byte>);
	static Botan::SecureVector<Botan::byte> PRF(Botan::OctetString, Botan::SecureVector<Botan::byte>, std::string, Botan::InitializationVector *);
	static void print_mpi (const char *name, gcry_mpi_t a);
	static gcry_mpi_t* createIHMEResultSet(int);
};


#endif /* UTIL_H_ */
