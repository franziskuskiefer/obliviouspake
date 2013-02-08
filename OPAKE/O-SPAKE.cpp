/*
 * O-SPAKE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"

OSpake::OSpake(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string crs) {
	this->G = G;
	this->M = M;
	this->N = N;
	this->crs = crs;
	finished = false;
}

void OSpake::init(std::vector<std::string> pwds, ROLE role, int c) {
	Spake *tmp = new Spake(this->G, this->M, this->N, this->crs);
	init(pwds, role, c, tmp);
}

// simple decoding (have only one BigInt there)
Botan::BigInt decodeMessage(message m){
	return Botan::BigInt("0x"+m.as_string());
}

mk OSpake::nextServer(message m){
	PrimeGroupAE ae(this->G);
	return nextServer(m, &ae, ae.getNae().getEll());
}

std::vector<message> decodeIncommingServer(message m){
	std::vector<message> result;
	result.push_back(m);
	return result;
}
Botan::BigInt encodeOutgoing(message m, AdmissibleEncoding *ae, bool *finished){
	// encode the client's messages (admissible encoding)
	Botan::BigInt out = Botan::BigInt("0x"+m.as_string());

	// we have only one message -> set finished
	*finished = true;

	// add admissible encoding
	return ae->encode(out);
}

mk OSpake::nextClient(message m){
	// Need this all over the place!
	PrimeGroupAE ae(this->G);

	encodeOutgoingMessage enc = &encodeOutgoing;
	decodeIncommingServerMessage dec = &decodeIncommingServer;
	return nextClient(m, ae.getNae().getEll(), enc, dec, &ae);
}

mk OSpake::next(message m) {
	std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
	if (this->procs[0]->getR() == SERVER) {
		return nextServer(m);
	} else {
		return nextClient(m);
	}
}

