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
RG_DDH::RG_DDH(Botan::DL_Group G, std::string id, PublicKey pk) {
	// Setup of Cramer-Shoup encryption scheme and according smooth-projective Hash function
	KeyPair kp;
	kp.pk = pk;
	this->cs.setKp(kp);

	this->csHash.keyGen(pk);
	this->ids = id;

	// empty instantiation of other variables // FIXME: really necessary?
	this->r = CLIENT;
}

/**
 * initialise the SPAKE state/instance
 */
void RG_DDH::init(std::string pwd, ROLE r){
	this->r = r;
	this->pwd = Util::pwdToBigInt(pwd);
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

void addCiphertext(std::vector<Botan::byte> &vec, Ciphertext &c){
	Botan::SecureVector<Botan::byte> tmp;
	tmp = Botan::BigInt::encode(c.u1);
	vec.insert(vec.end(), tmp.begin(), tmp.begin()+tmp.size());
	tmp = Botan::BigInt::encode(c.u2);
	vec.insert(vec.end(), tmp.begin(), tmp.begin()+tmp.size());
	tmp = Botan::BigInt::encode(c.e);
	vec.insert(vec.end(), tmp.begin(), tmp.begin()+tmp.size());
	tmp = Botan::BigInt::encode(c.v);
	vec.insert(vec.end(), tmp.begin(), tmp.begin()+tmp.size());
}

void RG_DDH::computeMacandKey(Botan::OctetString &t, Botan::OctetString &key){
	// shorten key first // XXX: security?
	Botan::Pipe hashPipe(new Botan::Hash_Filter("SHA-256"));
	hashPipe.process_msg(Botan::BigInt::encode(this->sk1));
	hashPipe.process_msg(Botan::BigInt::encode(this->sk2));

	key = Botan::SymmetricKey(hashPipe.read_all(0));
	Botan::Pipe macPipe(new Botan::MAC_Filter("CBC-MAC(AES-256)", key)); //HMAC(SHA-256)
	// create MAC input
	std::vector<Botan::byte> macIn;

	addCiphertext(macIn, this->c1);

	Botan::SecureVector<Botan::byte> tmp = Botan::BigInt::encode(this->s1);
	macIn.insert(macIn.end(), tmp.begin(), tmp.begin()+tmp.size());

	addCiphertext(macIn, this->c2);

	tmp = Botan::BigInt::encode(this->s2);
	macIn.insert(macIn.end(), tmp.begin(), tmp.begin()+tmp.size());

	macPipe.process_msg(&(macIn[0]), macIn.size());
	t = Botan::OctetString(macPipe.read_all(0));

	// xor with sk2
	Botan::OctetString toXor(hashPipe.read_all(1));
	t ^= toXor;

	// compute also final key
	key ^= toXor;
}

void RG_DDH::messageDecode(message m, Botan::BigInt &s, Ciphertext &c){
	Botan::OctetString encodedC, encodedS;
	decodeMessage(m, encodedC, encodedS);
	c = CramerShoup::decodeCiphertext(encodedC);
	s = Botan::BigInt(encodedS.begin(), encodedS.length());
}

void RG_DDH::messageEncode(message& m, Botan::BigInt s, Ciphertext c){
	m = encodeMessage(c, s);
}

Botan::BigInt RG_DDH::pwdToG(){
	return Botan::power_mod(this->cs.getKp().pk.G.get_g(), this->pwd, this->cs.getKp().pk.G.get_p());
}

/**
 * calculate next message based on incoming message
 */
mk RG_DDH::next(message m){
	mk result;
	if(m.length() == 0) { // at the first invocation the key is "null" --- here this can only happen once!
		this->c1 = this->cs.encrypt(pwdToG(), this->ids);
		result.m = CramerShoup::encodeCiphertext(this->c1);
	} else if (m.length() > 0 && this->s1 == 0 && this->c1.e == 0) { // Party gets first message --- FIXME: this won't work... how to identify first message?
		this->csHash.keyGen(this->cs.getKp().pk);
		this->c1 = CramerShoup::decodeCiphertext(m);
		this->s1 = this->csHash.project(this->c1, this->ids);
		X x;
		x.c = this->c1;
		x.m = pwdToG();
		this->sk1 = this->csHash.hash(x); // no label here necessary!

		std::vector<Botan::byte> tmpCVec;
		addCiphertext(tmpCVec, this->c1);
		this->c2 = this->cs.encrypt(pwdToG(), Botan::OctetString(&tmpCVec[0], tmpCVec.size()).as_string()+Botan::OctetString(Botan::BigInt::encode(this->s1)).as_string());

		result.m = encodeMessage(this->c2, this->s1);
	} else if (m.length() > 0 && this->c1.e != 0 && this->c2.e == 0) {
		this->csHash.keyGen(this->cs.getKp().pk);
		messageDecode(m, this->s1, this->c2);

		std::vector<Botan::byte> tmpCVec;
		addCiphertext(tmpCVec, this->c1);
		this->s2 = this->csHash.project(this->c2, Botan::OctetString(&tmpCVec[0], tmpCVec.size()).as_string()+Botan::OctetString(Botan::BigInt::encode(this->s1)).as_string());
		X x;
		x.c = this->c2;
		x.m = pwdToG();
		this->sk2 = this->csHash.hash(x); // no label here necessary!

		this->sk1 = Botan::power_mod(this->s1, this->cs.getR(), this->cs.getKp().pk.G.get_p());

		// compute MAC
		// shorten key first // XXX: security?
		Botan::OctetString t, key;
		computeMacandKey(t, key);

		// output s2 and t
		std::vector<Botan::byte> output;
		CramerShoup::addBigInt(this->s2, &output);
		output.insert(output.end(), t.begin(), t.begin()+t.length());
		result.m = Botan::OctetString(reinterpret_cast<const Botan::byte*>(&output[0]), output.size());

		this->k = key;
		result.k = key;
	} else if (m.length() > 0) { // last step for client: key computation and MAC check
		// get t and s2
		Botan::OctetString t, s;
		decodeMessage(m, t, s);
		this->s2 = Botan::BigInt(s.begin(), s.length());
		this->sk2 = Botan::power_mod(this->s2, this->cs.getR(), this->cs.getKp().pk.G.get_p());

		Botan::OctetString tCheck, key;
		computeMacandKey(tCheck, key);

		if (t == tCheck){
			result.k = key;
			this->k = key;
		} else {
//			std::cout << "Error! ----- MAC check failed!\n";
			// error...something went wrong, so we have no key
		}
	}

	return result;
}
