/*
 * O-SPAKE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"

OSpake::OSpake(Botan::DL_Group G, Botan::BigInt M, Botan::BigInt N, std::string crs) : ae(G){
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

mk OSpake::nextServer(message m){
	return nextServer(m, &this->ae, this->ae.getNae().getEll());
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
	encodeOutgoingMessage enc = &encodeOutgoing;
	return nextClient(m, this->ae.getNae().getEll(), enc, &this->ae);
}

mk OSpake::next(message m) {
#ifdef DEBUG
		std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
#endif
	if (this->procs[0]->getR() == SERVER) {
		return nextServer(m);
	} else {
		return nextClient(m);
	}
}

