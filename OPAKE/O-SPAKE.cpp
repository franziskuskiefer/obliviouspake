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
	Spake *tmp = new Spake(G, M, N, crs);
	this->procs.push_back(boost::shared_ptr<Pake>(tmp));
}

void OSpake::init(std::vector<std::string> pwds, ROLE role, int c) {
	if (role == CLIENT){
		for (int i = 1; i < c; ++i) {
			Spake *tmp = new Spake(this->G, this->M, this->N, this->crs);
			this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		}
		for(int i = 0; i < c ; ++i)
			this->procs[i]->init(pwds[i], role);
	} else { // there is only one instance for the server with one password
		this->procs[0]->init(pwds[0], role);
	}
}

mk OSpake::next(message m) {
	mk result;
	result = this->procs[0]->next(m);
	return result;
}

