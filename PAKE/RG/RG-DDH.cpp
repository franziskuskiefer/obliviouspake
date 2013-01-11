/*
 * RG-DDH.cpp
 *
 *  Created on: Dec 10, 2012
 *      Author: franziskus
 */

#include <stdio.h>
#include <iostream>
#include <memory>

#include "RG-DDH.h"

using namespace Botan;

/**
 * RG-DDH PAKE constructor, for general setup purposes (DL Group)
 */
RG_DDH::RG_DDH(Botan::DL_Group* G, std::string id, PublicKey *pk)
	{
	// Setup of Cramer-Shoup encryption scheme and according smooth-projective Hash function
	if (pk == 0)
		this->cs.keyGen(*G);
	else {
		KeyPair kp;
		kp.pk = *pk;
		this->cs.setKp(kp);
	}
	this->csHash.keyGen(*pk);
	this->ids = id;

	// empty instantiation of other variables // FIXME: really necessary?
	this->r = CLIENT;
}

/**
 * initialise the SPAKE state/instance
 */
void RG_DDH::init(std::string pwd, ROLE r){
	this->r = r;
	this->pwd = pwdToBigInt(pwd);
}

/**
 * calculate next message based on incoming message
 */
mk RG_DDH::next(message m){
	mk result;
	if(k.length() == 0) { // at the first invocation the key is "null" --- here this can only happen once!
		Ciphertext c = this->cs.encrypt(this->pwd, this->ids);
		result.m = CramerShoup::encodeCiphertext(c);
	}
	return result;
}
