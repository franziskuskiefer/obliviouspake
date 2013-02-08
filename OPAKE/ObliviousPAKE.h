/*
 * ObliviousPAKE.h
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#ifndef OBLIVIOUSPAKE_H_
#define OBLIVIOUSPAKE_H_

// OPAKE Compiler gets an PAKE as input
#include "../PAKE/pake.h"
// and uses IHME for message encoding
#include "../IHME/IHME.h"
// Admissible Encodings
#include "../AdmissibleEncoding/AdmissibleEncoding.h"

#include <boost/shared_ptr.hpp>

typedef std::vector<message> (*decodeIncommingServerMessage)(message m);
typedef Botan::BigInt (*encodeOutgoingMessage)(message m, AdmissibleEncoding *ae, bool *finished);
typedef Botan::OctetString (*encodeServerMessage)(std::vector<Botan::BigInt>);

class OPake {

protected:

	int c;
	bool finished;
	std::string crs;
	std::vector<boost::shared_ptr<Pake> > procs;
	std::vector<Botan::byte> sid;
	std::vector<Botan::OctetString> keys;


	void addElement(struct point*, int*, Botan::BigInt, Botan::BigInt);
	Botan::OctetString encodeS(gcry_mpi_t*, int);
	void keyGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *, std::vector<Botan::byte>);
	void confGen(Botan::OctetString, Botan::OctetString *, Botan::InitializationVector *, std::vector<Botan::byte>);
	Botan::SecureVector<Botan::byte> PRF(Botan::OctetString, Botan::SecureVector<Botan::byte>, std::string, Botan::InitializationVector *);
	mk finalServerMessage(mk);
	void decodeFinalMessage(message m, Botan::OctetString &ivKey, Botan::OctetString &ivConf, Botan::SecureVector<Botan::byte> &confVal);
	void splitFinalCombinedMessage(Botan::OctetString m, Botan::OctetString &min, Botan::OctetString &conf);
	gcry_mpi_t* MessageToS(Botan::OctetString, int);
	gcry_mpi_t** MessageToNuS(Botan::OctetString, int, int);
	Botan::BigInt ihmeDecode(message, int, Botan::BigInt, gcry_mpi_t p);
	Botan::OctetString nuIhmeDecode(message, int, int, Botan::BigInt, gcry_mpi_t p);
	gcry_mpi_t* createIHMEResultSet(int);
	gcry_mpi_t** createNuIHMEResultSet(int, int);
	Botan::OctetString encodeNuS(gcry_mpi_t **, int, int);

	mk nextServer(message m, AdmissibleEncoding *ae, Botan::BigInt P, encodeServerMessage enc = 0, int nu = 0);
	mk nextClient(message m, Botan::BigInt ihmeP, encodeOutgoingMessage encode, decodeIncommingServerMessage decode, AdmissibleEncoding *ae, int nu = 0);
	void init(std::vector<std::string> pwds, ROLE role, int c, Pake *p);

public:
	virtual void init(std::vector<std::string>, ROLE, int) = 0;
	virtual mk next(message) = 0;

	virtual ~OPake(){}

};

#endif /* OBLIVIOUSPAKE_H_ */
