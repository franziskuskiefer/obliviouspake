/*
 * CramerShoup.cpp
 *
 *  Created on: Jan 10, 2013
 *      Author: franziskus
 */


#include "CramerShoup.h"

CramerShoup::CramerShoup() {}

CramerShoup::CramerShoup(KeyPair kp) {
	this->kp = kp;
}

CramerShoup::CramerShoup(PublicKey pk) {
	this->kp.pk = pk;
}

void CramerShoup::keyGen(Botan::DL_Group G) {
	// tmp variables for performance...
	Botan::BigInt g = G.get_g();
	Botan::BigInt p = G.get_p();
	Botan::BigInt q = G.get_q();

	// make second generator
	Botan::BigInt alpha = Botan::BigInt::random_integer(this->rng, 0, q);
	do {
		this->kp.pk.g2 = Botan::power_mod(g, alpha, p);
	} while (this->kp.pk.g2 == 1);
	this->kp.pk.G = G;

	// generate secret random stuff
	this->kp.sk.x1 = Botan::BigInt::random_integer(this->rng, 0, q);
	this->kp.sk.x2 = Botan::BigInt::random_integer(this->rng, 0, q);
	this->kp.sk.y1 = Botan::BigInt::random_integer(this->rng, 0, q);
	this->kp.sk.y2 = Botan::BigInt::random_integer(this->rng, 0, q);
	this->kp.sk.z = Botan::BigInt::random_integer(this->rng, 0, q);

	// compute the public stuff
	this->kp.pk.c = (Botan::power_mod(g, this->kp.sk.x1, p)*Botan::power_mod(this->kp.pk.g2, this->kp.sk.x2, p)) % p;
	this->kp.pk.d = (Botan::power_mod(g, this->kp.sk.y1, p)*Botan::power_mod(this->kp.pk.g2, this->kp.sk.y2, p)) % p;
	this->kp.pk.h = Botan::power_mod(g, this->kp.sk.z, p);
}

// FIXME: is this correct?
Botan::BigInt CramerShoup::hashIt(Botan::BigInt u1, Botan::BigInt u2, Botan::BigInt e){
	Botan::SHA_256 h;
	h.update(Botan::BigInt::encode(u1));
	h.update(Botan::BigInt::encode(u2));
	h.update(Botan::BigInt::encode(e));
	return Botan::BigInt("0x"+Botan::OctetString(h.final()).as_string());
}

Ciphertext CramerShoup::encrypt(Botan::BigInt m) {
	Ciphertext c;

	// get the randomness
	this->r = Botan::BigInt::random_integer(this->rng, 0, this->kp.pk.G.get_q());

	// do the calculations
	c.u1 = Botan::power_mod(this->kp.pk.G.get_g(), this->r, this->kp.pk.G.get_p());
	c.u2 = Botan::power_mod(this->kp.pk.g2, this->r, this->kp.pk.G.get_p());
	c.e = (Botan::power_mod(this->kp.pk.h, this->r, this->kp.pk.G.get_p())*m) % this->kp.pk.G.get_p();
	Botan::BigInt tmp = hashIt(c.u1, c.u2, c.e);
	c.v = (Botan::power_mod(this->kp.pk.c, this->r, this->kp.pk.G.get_p())*Botan::power_mod(this->kp.pk.d, r*tmp, this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();

	return c;
}

Botan::BigInt CramerShoup::decrypt(Ciphertext c) {
	Botan::BigInt m;

	Botan::BigInt tmp = hashIt(c.u1, c.u2, c.e);
	Botan::BigInt check = (Botan::power_mod(c.u1, this->kp.sk.x1+(this->kp.sk.y1*tmp), this->kp.pk.G.get_p())*Botan::power_mod(c.u2, this->kp.sk.x2+(this->kp.sk.y2*tmp), this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();

	if (c.v == check){
		m = (c.e*Botan::inverse_mod(Botan::power_mod(c.u1, this->kp.sk.z, this->kp.pk.G.get_p()), this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();
	} else { // return an "Error"
		m = Botan::BigInt("-1");
	}

	return m;
}



