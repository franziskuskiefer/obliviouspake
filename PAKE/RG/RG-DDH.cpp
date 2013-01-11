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

// TODO: generalise with Carmer-Shoup cipher encoding
Botan::OctetString encodeMessage(Ciphertext c, Botan::BigInt s){
	Botan::OctetString encodedC = CramerShoup::encodeCiphertext(c);
	std::vector<Botan::byte> tmp;
	CramerShoup::addBigInt(s, &tmp);
	Botan::OctetString encodedS(reinterpret_cast<const Botan::byte*>(&tmp[0]), tmp.size());

	std::vector<Botan::byte> con;
	con.insert(con.end(), encodedS.begin(), encodedS.begin()+encodedS.length());
	con.insert(con.end(), encodedC.begin(), encodedC.begin()+encodedC.length());

	Botan::OctetString result(reinterpret_cast<const Botan::byte*>(&con[0]), con.size());
	return result;
}

void decodeMessage(Botan::OctetString in, Botan::OctetString &c, Botan::OctetString &s){
	Botan::u32bit elementLength = Botan::BigInt::decode(in.begin(), 8, Botan::BigInt::Binary).to_u32bit();
	s = Botan::OctetString(in.begin()+8*sizeof(Botan::byte), elementLength);

	c = Botan::OctetString(in.begin()+8*sizeof(Botan::byte)+elementLength, in.length()-8*sizeof(Botan::byte)-elementLength);
}

/**
 * calculate next message based on incoming message
 */
mk RG_DDH::next(message m){
	mk result;
	if(m.length() == 0) { // at the first invocation the key is "null" --- here this can only happen once!
		std::cout << "---next---0\n";
		this->c1 = this->cs.encrypt(this->pwd, this->ids);
		result.m = CramerShoup::encodeCiphertext(this->c1);
	} else if (m.length() > 0 && this->s1.size() == 0 && this->c1.e.size() == 0) { // Party gets first message --- FIXME: this won't work... how to identify first message?
		std::cout << "---next---1\n";
		this->csHash.keyGen(this->cs.getKp().pk);
		this->c1 = CramerShoup::decodeCiphertext(m);
		this->s1 = this->csHash.project(this->c1);
		X x;
		x.c = this->c1;
		x.m = this->pwd;
		Botan::BigInt sk = this->csHash.hash(x); // no label here necessary!
		this->c2 = this->cs.encrypt(this->pwd, m.as_string()+Botan::OctetString(Botan::BigInt::encode(this->s1)).as_string());

		result.m = encodeMessage(this->c2, this->s1);
	} else if (m.length() > 0 && this->c1.e.size() != 0) {
		std::cout << "---next---2\n";
		this->csHash.keyGen(this->cs.getKp().pk);
		Botan::OctetString encodedC, encodedS;
		decodeMessage(m, encodedC, encodedS);
		this->c2 = CramerShoup::decodeCiphertext(encodedC);
		this->s1 = Botan::BigInt(encodedS.begin(), encodedS.length());

		this->s2 = this->csHash.project(this->c2);
	}

	return result;
}
