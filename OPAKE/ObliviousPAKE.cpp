/*
 * ObliviousPAKE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "ObliviousPAKE.h"

// utility function to convert an OctetString to a gcrypt mpi
gcry_mpi_t* OPake::MessageToS(Botan::OctetString in, int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	size_t nscanned;
	Botan::u32bit elementLength = 0;
	unsigned long size = 0;
	for(int k = 0; k < numPwds; k++){
		S[k] = gcry_mpi_new(0);
		elementLength = Botan::BigInt::decode(in.begin()+k*8+size, 8, Botan::BigInt::Binary).to_u32bit();
		gcry_mpi_scan(&(S[k]), GCRYMPI_FMT_USG, in.begin()+(k+1)*8*sizeof(Botan::byte)+size, elementLength, &nscanned);
		size += elementLength;
	}
	return S;
}

Botan::BigInt OPake::ihmeDecode(message m, Botan::DL_Group G, int c, Botan::BigInt pwd){
	gcry_mpi_t p;
	Util::BigIntToMpi(&p, G.get_p());
	// get message from m to S
	gcry_mpi_t *S = MessageToS(m, c);
	// IHME decode
	gcry_mpi_t encoded_public_A_MPI, serverPwdNumMPI;
	Util::BigIntToMpi(&serverPwdNumMPI, pwd);
	encoded_public_A_MPI = gcry_mpi_new(0);
	decode(encoded_public_A_MPI,S,serverPwdNumMPI,c,p);
	return Util::MpiToBigInt(encoded_public_A_MPI);
}

// add an element to the IHME encode input structure P
void OPake::addElement(struct point *P, int *pos, Botan::BigInt pwd, Botan::BigInt m){
	// convert BigInts to MPIs
	gcry_mpi_t pwdMpi;
	Util::BigIntToMpi(&pwdMpi, pwd);
	gcry_mpi_t mMpi;
	Util::BigIntToMpi(&mMpi, m);

	// add (pwd, m) to P
	P[*pos].x = pwdMpi;
	P[*pos].y = mMpi;
	++*pos;
}

void OPake::addOctetString(Botan::OctetString toAdd, std::vector<Botan::byte> *vec) {
	Botan::SecureVector<Botan::byte> in(toAdd.begin(), toAdd.length());
	size_t size = in.size();
	for(size_t j = 0; j != sizeof(size_t); j++){
		vec->push_back(Botan::get_byte(j, size));
	}
	vec->insert(vec->end(), in.begin(), in.begin()+size);
}

Botan::OctetString OPake::encodeS(gcry_mpi_t *S, int c){
	std::vector<Botan::byte> vec;
	for(int i = 0; i < c; ++i) {
		unsigned char *buf;
		size_t length;
		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, &length, S[i]);
		Botan::OctetString tmpOct(buf, length);//ceil((double)gcry_mpi_get_nbits(S[i])/8));
		gcry_free (buf);
		addOctetString(tmpOct, &vec);
	}
	Botan::OctetString encoded(reinterpret_cast<const Botan::byte*>(&vec[0]), vec.size());
	return encoded;
}

// generate the final key of OSpake
void OPake::keyGen(Botan::OctetString K, Botan::OctetString *finalK, Botan::InitializationVector *iv, std::vector<Botan::byte> sid){
	std::string forKey = "1";
	// get S as byte vector
	Botan::SecureVector<Botan::byte> sidVec(&sid[0], sid.size());
	*finalK = Botan::OctetString(PRF(K, sidVec, forKey, iv));
}

// generate server confirmation message of OSpake
void OPake::confGen(Botan::OctetString K, Botan::OctetString *conf, Botan::InitializationVector *iv, std::vector<Botan::byte> sid){
	std::string forConf = "0";
	Botan::SecureVector<Botan::byte> sidVec(&sid[0], sid.size());
	*conf = Botan::OctetString(PRF(K, sidVec, forConf, iv));
}

// simulating a keyed PRF as AES encryption of the input
// FIXME: How to implement PRF correct?
Botan::SecureVector<Botan::byte> OPake::PRF(Botan::OctetString k, Botan::SecureVector<Botan::byte> sid, std::string indicator, Botan::InitializationVector *iv){
	Botan::AutoSeeded_RNG rng;
	if (iv->length() == 0)
		*iv = Botan::InitializationVector(rng, 16); // a random 128-bit IV

	Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", k, *iv, Botan::ENCRYPTION), new Botan::Hash_Filter("SHA-256"));

	std::string toEnc = Botan::OctetString(sid).as_string()+indicator;
	pipe.process_msg(toEnc);

	Botan::SecureVector<Botan::byte> out = pipe.read_all(0);

	return out;
}

// initializes an IHME result set S (output of IHME encode function)
gcry_mpi_t* OPake::createIHMEResultSet(int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	for(int k = 0; k < numPwds; k++)
		S[k] = gcry_mpi_new(0);
	return S;
}
