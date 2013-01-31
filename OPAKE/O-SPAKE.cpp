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
	finished = false;
}

void OSpake::init(std::vector<std::string> pwds, ROLE role, int c) {
	this->c = c;
	if (role == CLIENT){
		for (int i = 0; i < c; ++i) {
			Spake *tmp = new Spake(this->G, this->M, this->N, this->crs);
			this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		}
		for(int i = 0; i < c ; ++i)
			this->procs[i]->init(pwds[i], role);
	} else { // there is only one instance for the server with one password
		this->procs[0]->init(pwds[0], role);
	}
}

// simple decoding (have only one BigInt there)
Botan::BigInt decodeMessage(message m){
	return Botan::BigInt("0x"+m.as_string());
}

mk OSpake::next(message m) {
	mk result;
	std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
	if (this->procs[0]->getR() == SERVER) {
		Botan::OctetString messageIn;
		if (m.length() != 0){
			// get correct message first
			PrimeGroupAE ae(&this->G);
			Botan::BigInt aeDecodedM = ihmeDecode(m, this->G, c, this->procs[0]->getPwd());
			Botan::BigInt message = ae.decode(aeDecodedM);//decodeMessage(m)
			messageIn = Botan::OctetString(Botan::BigInt::encode(message));
		} else {
			messageIn = m;
		}
		result = this->procs[0]->next(messageIn);

		this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());
		this->sid.insert(this->sid.end(), result.m.begin(), result.m.begin()+result.m.length());

		// calculate confirmation message and real final key
		if (result.m.length() == 0){
			std::cout << "creating confirmation message and final key...\n";
			Botan::SecureVector<Botan::byte> confVal;
			Botan::OctetString finalK;
			Botan::InitializationVector ivKey, ivConf;
			keyGen(result.k, &finalK, &ivKey, this->sid);
			confGen(result.k, &result.m, &ivConf, this->sid);
			result.k = finalK;

			// add IVs to message
			std::vector<Botan::byte> out;
			addOctetString(result.m, &out);
			addOctetString(ivKey, &out);
			addOctetString(ivConf, &out);
			result.m = Botan::OctetString(reinterpret_cast<const Botan::byte*>(&out[0]), out.size());
		}
	} else { // this has to be a client....
		if (!this->finished){ // normal PAKE computations here
			// clear key vector
			this->keys.clear();
			// add incoming message to sid
			this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());

			struct point P[this->c];
			for (int k = 0; k < this->c; k++)
				initpoint(&P[k]);
			int pos = 0;
			for (int i = 0; i < this->c; ++i) { //FIXME: incoming m could be empty!
				mk piResult = this->procs[i]->next(m);
				if (piResult.m.length() == 0) {// there is no message anymore.... stop the bloody protocol
					// do not handle empty messages
					// FIXME: do we have to use random messages here?
					this->finished = true;
				} else { // only if there is really a message from Pi.next, we have to process it
					// encode the client's (Alice) messages (admissible encoding)
					PrimeGroupAE ae(&this->G);
					Botan::BigInt out = Botan::BigInt("0x"+piResult.m.as_string()); // FIXME: get BigInt direct from Pi!

					// add admissible encoding
					Botan::BigInt aeEncoded = ae.encode(out);

					// add out to IHME structure P
					addElement(P, &pos, this->procs[i]->getPwd(), aeEncoded);
				}

				// store also the key in the vector // FIXME: has to be done different!
				this->keys.insert(this->keys.end(), piResult.k);
			}
			result.k = this->keys[1]; // FIXME: have to return all keys....

			if (!this->finished){
				// compute IHME structure S from P with c passwords and modulus p
				gcry_mpi_t p;
				Util::BigIntToMpi(&p, this->G.get_p());
				gcry_mpi_t *S;
				S = createIHMEResultSet(this->c);
				interpolation_alg2(S, P, this->c, p);

				// have to encode the S as OctetString
				Botan::OctetString out = encodeS(S, this->c);
				result.m = out;
				this->sid.insert(this->sid.end(), out.begin(),out.begin()+out.length());

				// FIXME: when can we set finished?
				this->finished = true;
			}
		} else { // Here Pi finished and the incomming message is the confirmation message
			Botan::u32bit confLength = Botan::BigInt::decode(m.begin(), 8, Botan::BigInt::Binary).to_u32bit();
			Botan::SecureVector<Botan::byte> confVal(m.begin()+8*sizeof(Botan::byte), confLength);

			Botan::u32bit ivLength = Botan::BigInt::decode(m.begin()+8+confLength, 8, Botan::BigInt::Binary).to_u32bit();
			Botan::OctetString ivKey(m.begin()+2*8*sizeof(Botan::byte)+confLength, ivLength);
			Botan::OctetString ivConf(m.begin()+3*8*sizeof(Botan::byte)+confLength+ivLength, ivLength);

			// compute keys for Client
			for (int var = 0; var < this->c; ++var) {
				// generate confirmation message for every computed key
				Botan::OctetString conf;
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

