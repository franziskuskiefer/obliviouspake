/*
 * O-RGPAKE.cpp
 *
 *  Created on: Jan 31, 2013
 *      Author: franziskus
 */

#include "O-RGPAKE.h"

ORGpake::ORGpake(Botan::DL_Group* G, std::string crs, PublicKey* pk) {
	finished = false;
	this->pk = pk;
	this->G = *G;
}

// XXX: could be generalized...
void ORGpake::init(std::vector<std::string> pwds, ROLE role, int c) {
	this->c = c;
	if (role == CLIENT){
		for (int i = 0; i < c; ++i) {
			RG_DDH *tmp = new RG_DDH(&(this->G), this->crs, this->pk);
			this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		}
		for(int i = 0; i < c ; ++i){
			this->procs[i]->init(pwds[i], role);
		}
	} else { // there is only one instance for the server with one password
		RG_DDH *tmp = new RG_DDH(&(this->G), this->crs, this->pk);
		this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		this->procs[0]->init(pwds[0], role);
	}
}

mk ORGpake::nextServer(message m){
	mk result;
	Botan::OctetString messageIn;
	if (m.length() != 0){
		// get correct message first
		PrimeGroupAE ae(&this->G);
		gcry_mpi_t p;
		Util::BigIntToMpi(&p, ae.getNae().getEll());
		int nu = 5;
		Botan::OctetString aeDecodedM = nuIhmeDecode(m, this->G, c, nu, this->procs[0]->getPwd(), p);
		size_t length = ae.getNae().getEll().bits()/8;
		Botan::BigInt s = Botan::BigInt::decode(aeDecodedM.begin(), length, Botan::BigInt::Binary);
		Botan::BigInt u1 = Botan::BigInt::decode(aeDecodedM.begin()+length, length, Botan::BigInt::Binary);
		Botan::BigInt u2 = Botan::BigInt::decode(aeDecodedM.begin()+2*length, length, Botan::BigInt::Binary);
		Botan::BigInt e = Botan::BigInt::decode(aeDecodedM.begin()+3*length, length, Botan::BigInt::Binary);
		Botan::BigInt v = Botan::BigInt::decode(aeDecodedM.begin()+4*length, length, Botan::BigInt::Binary);
		s = ae.decode(s);
		u1 = ae.decode(u1);
		u2 = ae.decode(u2);
		e = ae.decode(e);
		v = ae.decode(v);
		Ciphertext c = {u1, u2, e, v};
		RG_DDH::messageEncode(messageIn, s, c);
	} else {
		messageIn = m;
	}
	result = this->procs[0]->next(messageIn);

	this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());
	this->sid.insert(this->sid.end(), result.m.begin(), result.m.begin()+result.m.length());

	// calculate confirmation message and real final key
	if (result.k.length() != 0){
		std::cout << "creating confirmation message and final key...\n";
		mk finalResult = finalServerMessage(result);
		// replace key in result and append confirmation message to last RG-PAKE message
		result.k = finalResult.k;
		Util::OctetStringConcat(result.m, finalResult.m, false);
	}

	return result;
}

mk ORGpake::nextClient(message m){
	mk result;

	if (!this->finished){ // normal PAKE computations here
		// clear key vector
		this->keys.clear();
		// add incoming message to sid
		this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());

		// prepare IHME stuff
		int nu = 5; // we have 5 elements per message in RG-PAKE
		struct point P[this->c];
		for (int k = 0; k < this->c; k++)
			initpoint(&P[k]);
		int pos = 0;

		// prepare Admissible Encoding
		PrimeGroupAE ae(&this->G);

		// Iterate over pake instances
		//FIXME: incoming m could be empty! -> really?
		for (int i = 0; i < this->c; ++i) {
			mk piResult = this->procs[i]->next(m);
			if (piResult.m.length() == 0) {// there is no message anymore.... stop the bloody protocol
				// do not handle empty messages
				// FIXME: do we have to use random messages here, or can we just stop the compiler and output the key?
				std::cout << "----------------- ERROR (one PAKE instance returned an empty message) -----------------";
			} else { // only if there is really a message from Pi.next, we have to process it
				// encode the client's messages (admissible encoding)
				// TODO: generalize this!
				Ciphertext c;
				Botan::BigInt s;
				RG_DDH::messageDecode(piResult.m, s, c);

				Botan::OctetString encs(Botan::BigInt::encode(ae.encode(s)));
				Botan::OctetString encu1(Botan::BigInt::encode(ae.encode(c.u1)));
				Botan::OctetString encu2(Botan::BigInt::encode(ae.encode(c.u2)));
				Botan::OctetString ence(Botan::BigInt::encode(ae.encode(c.e)));
				Botan::OctetString encv(Botan::BigInt::encode(ae.encode(c.v)));

				std::vector<Botan::byte> tmp;
				Botan::OctetString *ens[5] = {&encs, &encu1, &encu2, &ence, &encv};
				for (int j = 0; j < 5; ++j) {
					int i = (ae.getNae().getEll().bits()/8) - ens[j]->length();
					while (i > 0){
						std::cout << "have to pad with zeros....\n";
						tmp.push_back((Botan::byte)0);
						--i;
					}
					tmp.insert(tmp.end(), ens[j]->begin() ,ens[j]->begin()+ens[j]->length());
				}
				Botan::BigInt aeEns = Botan::BigInt::decode(Botan::SecureVector<Botan::byte>(&(tmp[0]), tmp.size()));

				// add admissible encoding and add out to IHME structure P
				addElement(P, &pos, this->procs[i]->getPwd(), aeEns);
			}

			// store also the key in the vector // FIXME: has to be done different!
			this->keys.insert(this->keys.end(), piResult.k);
		}
		result.k = this->keys[1]; // FIXME: have to return all keys....

		// compute IHME structure S from P with c passwords and modulus p
		gcry_mpi_t p;
		Util::BigIntToMpi(&p, ae.getNae().getEll());
		gcry_mpi_t **S;
		S = createNuIHMEResultSet(this->c, nu);
		v_fold_interleaving_encode(S, P, nu, this->c,p);

		// have to encode the S as OctetString
		Botan::OctetString out = encodeNuS(S, this->c, nu);
		result.m = out;
		this->sid.insert(this->sid.end(), out.begin(),out.begin()+out.length());

		// in RG PAKE client sends only one message!
		this->finished = true;
	} else { // The incoming message is the confirmation message AND the last RG PAKE message
		std::cout << "PAKE finished ... " << std::endl;

		// first cut the server message to get confirmation values and original message
		Botan::OctetString min, conf;
		splitFinalCombinedMessage(m, min, conf);

		// add incoming message to sid (only min, conf needs sid)
		this->sid.insert(this->sid.end(), min.begin(), min.begin()+min.length());

		// we have to run RG PAKE a last time at first
		// clear key vector first
		this->keys.clear();
		for (int i = 0; i < this->c; ++i) {
			mk piResult = this->procs[i]->next(min);
			// store also the key in the vector // FIXME: has to be done different!
			this->keys.insert(this->keys.end(), piResult.k);
		}

		// decode the confirmation message from the server
		Botan::OctetString ivKey, ivConf;
		Botan::SecureVector<Botan::byte> confVal;
		decodeFinalMessage(conf, ivKey, ivConf, confVal);

		// compute keys for Client
		for (int var = 0; var < this->c; ++var) {
			// generate confirmation message for every computed key
			Botan::OctetString conf;
			if (this->keys[var].length() != 0) {
				confGen(this->keys[var], &conf, &ivConf, this->sid);

				if (conf == confVal){
					std::cout << "got the key :)\n";
					keyGen(this->keys[var], &result.k, &ivKey, this->sid);
					break; // XXX: we can stop when we found the correct key; Problem: Side-Channel Attacks
				}
			}
		}
	}

	return result;
}

mk ORGpake::next(message m) {
	std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
	if (this->procs[0]->getR() == SERVER) {
		return nextServer(m);
	} else { // this has to be a client....
		return nextClient(m);
	}
}

