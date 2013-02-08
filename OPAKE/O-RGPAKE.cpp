/*
 * O-RGPAKE.cpp
 *
 *  Created on: Jan 31, 2013
 *      Author: franziskus
 */

#include "O-RGPAKE.h"

ORGpake::ORGpake(Botan::DL_Group G, std::string crs, PublicKey pk) {
	finished = false;
	this->pk = pk;
	this->G = G;
}

void ORGpake::init(std::vector<std::string> pwds, ROLE role, int c) {
	RG_DDH *tmp = new RG_DDH(this->G, this->crs, this->pk);
	init(pwds, role, c, tmp);
}

Botan::OctetString encodeOutgoingServerMessage(std::vector<Botan::BigInt> in){
	Ciphertext c = {in[1], in[2], in[3], in[4]};
	Botan::OctetString result;
	RG_DDH::messageEncode(result, in[0], c);
	return result;
}

mk ORGpake::nextServer(message m){
	PrimeGroupAE ae(this->G);

	encodeServerMessage enc = &encodeOutgoingServerMessage;
	return nextServer(m, &ae, ae.getNae().getEll(), enc, 5);
}

std::vector<message> decodeIncommingServer(message m){
	std::vector<message> result;

	// first cut the server message to get confirmation values and original message
	Botan::OctetString min, conf;
	Util::splitFinalCombinedMessage(m, min, conf);
	result.push_back(conf);
	result.push_back(min);

	return result;
}

Botan::BigInt encodeOutgoing(message m, AdmissibleEncoding *ae, bool *finished){
	Ciphertext c;
	Botan::BigInt s;
	RG_DDH::messageDecode(m, s, c);

	Botan::OctetString encs(Botan::BigInt::encode(ae->encode(s)));
	Botan::OctetString encu1(Botan::BigInt::encode(ae->encode(c.u1)));
	Botan::OctetString encu2(Botan::BigInt::encode(ae->encode(c.u2)));
	Botan::OctetString ence(Botan::BigInt::encode(ae->encode(c.e)));
	Botan::OctetString encv(Botan::BigInt::encode(ae->encode(c.v)));

	std::vector<Botan::byte> tmp;
	Botan::OctetString *ens[5] = {&encs, &encu1, &encu2, &ence, &encv};
	for (int j = 0; j < 5; ++j) {
		int i = (((PrimeGroupAE*)ae)->getNae().getEll().bits()/8) - ens[j]->length();
		while (i > 0){
			tmp.push_back((Botan::byte)0);
			--i;
		}
		tmp.insert(tmp.end(), ens[j]->begin() ,ens[j]->begin()+ens[j]->length());
	}

	// we have only one message -> set finished
	*finished = true;

	// add admissible encoding
	return Botan::BigInt::decode(Botan::SecureVector<Botan::byte>(&(tmp[0]), tmp.size()));
}

mk ORGpake::nextClient(message m){
	// Need this all over the place!
	PrimeGroupAE ae(this->G);

	encodeOutgoingMessage enc = &encodeOutgoing;
	decodeIncommingServerMessage dec = &decodeIncommingServer;
	return nextClient(m, ae.getNae().getEll(), enc, &ae, dec, 5);
}

mk ORGpake::next(message m) {
	std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
	if (this->procs[0]->getR() == SERVER) {
		return nextServer(m);
	} else { // this has to be a client....
		return nextClient(m);
	}
}

