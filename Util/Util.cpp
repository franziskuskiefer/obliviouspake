/*
 * Util.cpp
 *
 *  Created on: Jan 16, 2013
 *      Author: franziskus
 */

#include "Util.h"

// utility function to convert a Botan BigInt to a gcrypt mpi
void Util::BigIntToMpi(gcry_mpi_t *mpiResult, Botan::BigInt in){
	Botan::SecureVector<Botan::byte> tmp = Botan::BigInt::encode(in);
	*mpiResult = gcry_mpi_new(0);
	size_t nscanned;
	gcry_mpi_scan(mpiResult, GCRYMPI_FMT_USG, tmp.begin(), tmp.size(), &nscanned);
}


// utility function to convert a gcrypt mpi to a Botan BigInt
Botan::BigInt Util::MpiToBigInt(gcry_mpi_t in){
	unsigned char *buf;
	gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, in);
	Botan::BigInt bigIntResult = Botan::BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), Botan::BigInt::Binary);
	gcry_free (buf);

	return bigIntResult;
}

/**
 * Utility function to convert a password string into a BigInt
 */
Botan::BigInt Util::pwdToBigInt(std::string pwd){
	const Botan::byte* pwdB = (Botan::byte*)&pwd[0];
	return Botan::BigInt::decode(pwdB, pwd.length(), Botan::BigInt::Binary);
}

// utility function for mpi printing
void Util::print_mpi (const char *name, gcry_mpi_t a) {
	unsigned char *buf;

	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, a);

	printf ("%s: %s\n", name, buf);
	gcry_free (buf);
}

