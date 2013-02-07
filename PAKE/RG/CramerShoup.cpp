/*
 * CramerShoup.cpp
 *
 *  Created on: Jan 10, 2013
 *      Author: franziskus
 */


#include "CramerShoup.h"
#include <sstream>

CramerShoup::CramerShoup() {}

CramerShoup::CramerShoup(KeyPair kp) {
	this->kp = kp;
}

CramerShoup::CramerShoup(PublicKey pk) {
	this->kp.pk = pk;
}

void CramerShoup::keyGen(Botan::DL_Group G) {
	Botan::AutoSeeded_RNG rng;

	// tmp variables ...
	Botan::BigInt g = G.get_g();
	Botan::BigInt p = G.get_p();
	Botan::BigInt q = G.get_q();

	// make second generator
	Botan::BigInt alpha = Botan::BigInt::random_integer(rng, 0, q);
	do {
		this->kp.pk.g2 = Botan::power_mod(g, alpha, p);
	} while (this->kp.pk.g2 == 1);
	this->kp.pk.G = G;

	// generate secret random stuff
	this->kp.sk.x1 = Botan::BigInt::random_integer(rng, 0, q);
	this->kp.sk.x2 = Botan::BigInt::random_integer(rng, 0, q);
	this->kp.sk.y1 = Botan::BigInt::random_integer(rng, 0, q);
	this->kp.sk.y2 = Botan::BigInt::random_integer(rng, 0, q);
	this->kp.sk.z = Botan::BigInt::random_integer(rng, 0, q);

	// compute the public stuff
	this->kp.pk.c = (Botan::power_mod(g, this->kp.sk.x1, p)*Botan::power_mod(this->kp.pk.g2, this->kp.sk.x2, p)) % p;
	this->kp.pk.d = (Botan::power_mod(g, this->kp.sk.y1, p)*Botan::power_mod(this->kp.pk.g2, this->kp.sk.y2, p)) % p;
	this->kp.pk.h = Botan::power_mod(g, this->kp.sk.z, p);
}

// FIXME: is this correct?
Botan::BigInt CramerShoup::hashIt(Botan::BigInt u1, Botan::BigInt u2, Botan::BigInt e, std::string l){
	Botan::SHA_256 h;
	h.update(Botan::BigInt::encode(u1));
	h.update(Botan::BigInt::encode(u2));
	h.update(Botan::BigInt::encode(e));
	h.update(l);
	return Botan::BigInt("0x"+Botan::OctetString(h.final()).as_string());
}

Ciphertext CramerShoup::encrypt(Botan::BigInt m, std::string l) {
	Ciphertext c;
	Botan::AutoSeeded_RNG rng;

	// get the randomness
	this->r = Botan::BigInt::random_integer(rng, 0, this->kp.pk.G.get_q());

	// do the calculations
	c.u1 = Botan::power_mod(this->kp.pk.G.get_g(), this->r, this->kp.pk.G.get_p());
	c.u2 = Botan::power_mod(this->kp.pk.g2, this->r, this->kp.pk.G.get_p());
	c.e = (Botan::power_mod(this->kp.pk.h, this->r, this->kp.pk.G.get_p())*m) % this->kp.pk.G.get_p();
	Botan::BigInt tmp = hashIt(c.u1, c.u2, c.e, l);
	c.v = (Botan::power_mod(this->kp.pk.c, this->r, this->kp.pk.G.get_p())*Botan::power_mod(this->kp.pk.d, r*tmp, this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();

	return c;
}

// XXX: unused, so not well tested!
Botan::BigInt CramerShoup::decrypt(Ciphertext c, std::string l) {
	Botan::BigInt m;

	Botan::BigInt tmp = hashIt(c.u1, c.u2, c.e, l);
	Botan::BigInt check = (Botan::power_mod(c.u1, this->kp.sk.x1+(this->kp.sk.y1*tmp), this->kp.pk.G.get_p())*Botan::power_mod(c.u2, this->kp.sk.x2+(this->kp.sk.y2*tmp), this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();

	if (c.v == check){
		m = (c.e*Botan::inverse_mod(Botan::power_mod(c.u1, this->kp.sk.z, this->kp.pk.G.get_p()), this->kp.pk.G.get_p())) % this->kp.pk.G.get_p();
	} else { // return an "Error"
		m = Botan::BigInt("-1");
	}

	return m;
}

void CramerShoup::addBigInt(Botan::BigInt toAdd, std::vector<Botan::byte> *vec) {
	Botan::SecureVector<Botan::byte> in = Botan::BigInt::encode(toAdd);
	size_t size = in.size();
	for(size_t j = 0; j != sizeof(size_t); j++){
		vec->push_back(Botan::get_byte(j, size));
	}
	vec->insert(vec->end(), in.begin(), in.begin()+size);
}

Ciphertext CramerShoup::decodeCiphertext(Botan::OctetString in){
	Ciphertext c;

	Botan::u32bit elementLength = 0;
	unsigned long size = 0;
	Botan::BigInt* ciphers[] = {&c.u1, &c.u2, &c.e, &c.v};
	for(int k = 0; k < 4; k++){
		elementLength = Botan::BigInt::decode(in.begin()+k*8+size, 8, Botan::BigInt::Binary).to_u32bit();
		*(ciphers[k]) = Botan::BigInt::decode(in.begin()+(k+1)*8*sizeof(Botan::byte)+size, elementLength);
		size += elementLength;
	}

	return c;
}

Botan::OctetString CramerShoup::encodeCiphertext(Ciphertext c){
	std::vector<Botan::byte> tmp;

	addBigInt(c.u1, &tmp);
	addBigInt(c.u2, &tmp);
	addBigInt(c.e, &tmp);
	addBigInt(c.v, &tmp);

	Botan::OctetString encoded(reinterpret_cast<const Botan::byte*>(&tmp[0]), tmp.size());

	return encoded;
}

void CramerShoup::printCiphertext(Ciphertext c){
	std::cout << "Ciphertext\n";
	std::cout << "u1: " << std::hex << c.u1;
	std::cout << "\nu2: " << std::hex << c.u2;
	std::cout << "\ne: " << std::hex << c.e;
	std::cout << "\nv: " << std::hex << c.v << "\n";
}
