/*
 * CramerShoupSPHash.cpp
 *
 *  Created on: Jan 10, 2013
 *      Author: franziskus
 */

#include "CramerShoupSPHash.h"

CramerShoupSPHash::CramerShoupSPHash() {}

CramerShoupSPHash::CramerShoupSPHash(Key k, PublicKey pk) {
	this->pk = pk;
	this->k = k;
}

void CramerShoupSPHash::keyGen(PublicKey pk) {
	Botan::AutoSeeded_RNG rng;

	this->pk = pk;
	this->k.a = Botan::BigInt::random_integer(rng, 0, pk.G.get_q());
	this->k.b = Botan::BigInt::random_integer(rng, 0, pk.G.get_q());
	this->k.c = Botan::BigInt::random_integer(rng, 0, pk.G.get_q());
	this->k.d = Botan::BigInt::random_integer(rng, 0, pk.G.get_q());
}

Botan::BigInt CramerShoupSPHash::project(Ciphertext c, std::string l) {
	Botan::BigInt s;

	Botan::BigInt hash = CramerShoup::hashIt(c.u1, c.u2, c.e, l);

	s =
		(Botan::power_mod(this->pk.G.get_g(), this->k.a, this->pk.G.get_p())
		*Botan::power_mod(this->pk.g2, this->k.b, this->pk.G.get_p())
		*Botan::power_mod(this->pk.h, this->k.c, this->pk.G.get_p())
		*Botan::power_mod(this->pk.c, this->k.d, this->pk.G.get_p())
		*Botan::power_mod(this->pk.d, this->k.d*hash, this->pk.G.get_p()))
		% this->pk.G.get_p();

	return s;
}

Botan::BigInt CramerShoupSPHash::hash(X x) {
	Botan::BigInt h;

	h =
		(Botan::power_mod(x.c.u1, this->k.a, this->pk.G.get_p())
		*Botan::power_mod(x.c.u2, this->k.b, this->pk.G.get_p())
		*Botan::power_mod(x.c.e, this->k.c, this->pk.G.get_p())
		*Botan::inverse_mod(Botan::power_mod(x.m, this->k.c, this->pk.G.get_p()), this->pk.G.get_p())
		*Botan::power_mod(x.c.v, this->k.d, this->pk.G.get_p()))
		% this->pk.G.get_p();

	return h;
}

