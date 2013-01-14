/*
 * oSpake.cpp
 *
 *  Created on: Dec 10, 2012
 *      Author: franziskus
 */

#include <stdio.h>
#include <iostream>
#include <memory>

#include "Spake.h"

#define BILLION 1000000000L

using namespace Botan;

OctetString hashIt(std::string params, BigInt A, BigInt B, BigInt pwd, BigInt K){
	SHA_256 h;
	h.update(params);
	h.update(BigInt::encode(A));
	h.update(BigInt::encode(B));
	h.update(BigInt::encode(pwd));
	h.update(BigInt::encode(K));
	return OctetString(h.final());
}

BigInt createMessage(DH_PrivateKey privateKey, BigInt pwd, DL_Group G, BigInt M){
	return (privateKey.get_y()*(power_mod(M, pwd, G.get_p()))) % G.get_p();
}

BigInt computeKey(BigInt publicValue, BigInt pwd, BigInt publicKey, DH_PrivateKey privateKey, DL_Group G){
	BigInt NPW = power_mod(publicValue, pwd, G.get_p());
	return power_mod(publicKey*(inverse_mod(NPW, G.get_p())), privateKey.get_x(), G.get_p());
}

/**
 * Spake constructor, for general setup purposes (DL Group)
 */
Spake::Spake(Botan::DL_Group* G, Botan::BigInt* M, Botan::BigInt* N, std::string crs)
	{
	this->G = *G;
	this->M = *M;
	this->N = *N;
	this->crs = crs;

	// empty instantiation of other variables // FIXME: really necessary?
	this->r = CLIENT;
}

/**
 * initialise the SPAKE state/instance
 */
void Spake::init(std::string pwd, ROLE r){
	this->r = r;
	this->pwd = pwdToBigInt(pwd);
}

/**
 * calculate next message based on incoming message
 */
mk Spake::next(message m){
	mk result;
	if(k.length() == 0) { // at the first invocation the key is "null"
		if (this->privateKey == NULL && m.length() == 0) { // we have to calculate private and public DH key first && m has to be 0, otherwise we have to do more things at once
			Botan::DH_PrivateKey *tmp = new Botan::DH_PrivateKey(this->rng, this->G);
			this->privateKey = boost::shared_ptr<Botan::DH_PrivateKey>(tmp);
			if (r == CLIENT){ // compute client message (with M)
				this->publicKey = createMessage(*(this->privateKey), this->pwd, this->G, this->M);
			} else { // compute server message (with N)
				this->publicKey = createMessage(*(this->privateKey), this->pwd, this->G, this->N);
			}
			result.m = Botan::OctetString(Botan::BigInt::encode(this->publicKey));
		} else if (this->privateKey != NULL) { // we have calculated public values already and got a message -> compute key from everything
			// The incoming message is the public Value as BigInt
			Botan::BigInt Y = Botan::BigInt("0x"+m.as_string());
			// compute k
			BigInt K;
			if (this->r == CLIENT){ // use N for Client
				K = computeKey(this->N, this->pwd, Y, *(this->privateKey), this->G);
				// calculates the actual keys
				result.k = hashIt(this->crs, Y, this->publicKey, this->pwd, K);
			} else { // use M for Server
				K = computeKey(this->M, this->pwd, Y, *(this->privateKey), this->G);
				// calculates the actual keys
				result.k = hashIt(this->crs, this->publicKey, Y, this->pwd, K);
			}
		} else { // we have nothing yet, but a message from the other party -> rock on!
			// The incoming message is the public Value as BigInt
			Botan::BigInt Y = Botan::BigInt("0x"+m.as_string());

			// Generate private/public DH Key
			Botan::DH_PrivateKey *tmp = new Botan::DH_PrivateKey(this->rng, this->G);
			this->privateKey = boost::shared_ptr<Botan::DH_PrivateKey>(tmp);
			if (r == CLIENT){ // compute client message (with M)
				this->publicKey = createMessage(*(this->privateKey), this->pwd, this->G, this->M);
			} else { // compute server message (with N)
				this->publicKey = createMessage(*(this->privateKey), this->pwd, this->G, this->N);
			}
			result.m = Botan::OctetString(Botan::BigInt::encode(this->publicKey));

			// Calculate final key
			BigInt K;
			if (r == CLIENT){ // use N for Client
				K = computeKey(this->N, this->pwd, Y, *(this->privateKey), this->G);
				// calculates the actual keys
				result.k = hashIt(this->crs, Y, this->publicKey, this->pwd, K);
				this->k = result.k;
			} else { // use M for Server
				K = computeKey(this->M, this->pwd, Y, *(this->privateKey), this->G);
				// calculates the actual keys
				result.k = hashIt(this->crs, this->publicKey, Y, this->pwd, K);
				this->k = result.k;
			}
		}
	}
	return result;
}
