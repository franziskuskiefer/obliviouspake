/*
 * PrimeGroupAE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "PrimeGroupAE.h"

PrimeGroupAE::PrimeGroupAE(Botan::DL_Group* G) {
	this->G = *G;

	// generate Z_P^*
	this->Z = generate_Z();
}

// The admissible encoding function for one group element of G
Botan::BigInt PrimeGroupAE::encode(Botan::BigInt m) {
	Botan::AutoSeeded_RNG rng;
	Botan::BigInt gpowq = Botan::power_mod(this->Z.g, G.get_q(), this->Z.p);
	Botan::BigInt r = Botan::BigInt::random_integer(rng, 0, this->Z.a);
	Botan::BigInt gpowqr = Botan::power_mod(gpowq, r, this->Z.p);
	Botan::BigInt mpowainv = Botan::power_mod(m, Botan::inverse_mod(this->Z.a, G.get_q()), this->Z.p);
	return (gpowqr*mpowainv) % this->Z.p;
}

// admissible decoding for a group element of G
Botan::BigInt PrimeGroupAE::decode(Botan::BigInt c) {
	return Botan::power_mod(c, this->Z.a, G.get_p());
}

// generate the z_p_star structure for a DL group G
z_p_star PrimeGroupAE::generate_Z(){
	// generate p' = a*p+1
	Botan::BigInt q = G.get_q();
	bool found = false;
	Botan::BigInt a = 2;
	Botan::BigInt pp;
	z_p_star result;
	while(!found){
		if (gcd(a, q) == 1){
			pp = a*q+1;
			if (Botan::check_prime(pp, this->rng)){
				found = true;
				result.p = pp;
				result.a = a;
				Botan::BigInt gg;
				bool error = false;
				do {
					// get a generator for G=Z_p^*
					gg = Botan::BigInt::random_integer(this->rng, 2, pp);
					if (Botan::power_mod(gg, q, pp) == 1){ // first check that we do not generate G_q
						// make prime factorization of a to check that g generates complete Z_p^*
						std::vector<Botan::BigInt> factors = primeFactors(a);
						for(std::vector<Botan::BigInt>::const_iterator i = factors.begin(); i != factors.end(); ++i)
							if (Botan::power_mod(gg, *i, pp) == 1)
								error = true;
					}
				} while (error);
				result.g = gg;
			} else {
				++a;
			}
		} else { // XXX: this happens with modp/ietf/6144 and 8192
			++a;
		}
	}
	return result;
}

std::vector<Botan::BigInt> PrimeGroupAE::primeFactors(Botan::BigInt n){
	std::vector<Botan::BigInt> factorization;

	if (n == 2) { // trivial case 1
		factorization.push_back(n);
		return factorization;
	}

	if (Botan::check_prime(n, this->rng)) { // trivial case 2
		factorization.push_back(n);
		return factorization;
	}

	Botan::BigInt d(2);
	while (n > 1){
		if (Botan::check_prime(d, this->rng)){
			if (n%d == 0) {
				n=n/d;
				factorization.push_back(d);
			}
			while (n%d == 0)
				n=n/d;
		}
		d++;
	}

	return factorization;
}
