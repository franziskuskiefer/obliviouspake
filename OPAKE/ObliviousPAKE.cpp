/*
 * ObliviousPAKE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "ObliviousPAKE.h"

// utility function to convert an OctetString to a gcrypt mpi
gcry_mpi_t* OPake::MessageToS(Botan::OctetString in, int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	size_t nscanned;
	Botan::u32bit elementLength = 0;
	unsigned long size = 0;
	for(int k = 0; k < numPwds; k++){
		S[k] = gcry_mpi_new(0);
		elementLength = Botan::BigInt::decode(in.begin()+k*8+size, 8, Botan::BigInt::Binary).to_u32bit();
		gcry_mpi_scan(&(S[k]), GCRYMPI_FMT_USG, in.begin()+(k+1)*8*sizeof(Botan::byte)+size, elementLength, &nscanned);
		size += elementLength;
	}
	return S;
}

// utility function to convert an OctetString to a gcrypt mpi
gcry_mpi_t** OPake::MessageToNuS(Botan::OctetString in, int numPwds, int nu){
	gcry_mpi_t **S;
	S = (gcry_mpi_t**)calloc(nu, sizeof(gcry_mpi_t*));
	Botan::u32bit elementLength = 0;
	size_t nscanned;
	unsigned long size = 0;
	for (int i = 0; i < nu; ++i) {
		S[i] = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
		for(int k = 0; k < numPwds; k++){
			S[i][k] = gcry_mpi_new(0);
			elementLength = Botan::BigInt::decode(in.begin()+((k+i*numPwds)*8)+size, 8, Botan::BigInt::Binary).to_u32bit();
			gcry_mpi_scan(&(S[i][k]), GCRYMPI_FMT_USG, in.begin()+(k+1+i*numPwds)*8*sizeof(Botan::byte)+size, elementLength, &nscanned);
			size += elementLength;
		}
	}
	return S;
}

Botan::BigInt OPake::ihmeDecode(message m, int c, Botan::BigInt pwd, gcry_mpi_t p){
	// get message from m to S
	gcry_mpi_t *S = MessageToS(m, c);
	// IHME decode
	gcry_mpi_t encoded_public_A_MPI, serverPwdNumMPI;
	Util::BigIntToMpi(&serverPwdNumMPI, pwd);
	encoded_public_A_MPI = gcry_mpi_new(0);
	decode(encoded_public_A_MPI,S,serverPwdNumMPI,c,p);
	return Util::MpiToBigInt(encoded_public_A_MPI);
}

Botan::OctetString OPake::nuIhmeDecode(message m, int c, int nu, Botan::BigInt pwd, gcry_mpi_t p){
	// get message from m to S
	gcry_mpi_t **S = MessageToNuS(m, c, nu);
	// IHME decode
	gcry_mpi_t encoded_public_A_MPI, serverPwdNumMPI;
	Util::BigIntToMpi(&serverPwdNumMPI, pwd);
	encoded_public_A_MPI = gcry_mpi_new(0);
	v_fold_interleaving_decode(encoded_public_A_MPI,S,serverPwdNumMPI, nu, c, p);
	return Util::MpiToOctetString(encoded_public_A_MPI);
}

// add an element to the IHME encode input structure P
void OPake::addElement(struct point *P, int *pos, Botan::BigInt pwd, Botan::BigInt m){
	// convert BigInts to MPIs
	gcry_mpi_t pwdMpi;
	Util::BigIntToMpi(&pwdMpi, pwd);
	gcry_mpi_t mMpi;
	Util::BigIntToMpi(&mMpi, m);

	// add (pwd, m) to P
	P[*pos].x = pwdMpi;
	P[*pos].y = mMpi;
	++*pos;
}

Botan::OctetString OPake::encodeS(gcry_mpi_t *S, int c){
	std::vector<Botan::byte> vec;
	for(int i = 0; i < c; ++i) {
		unsigned char *buf;
		size_t length;
		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, &length, S[i]);
		Botan::OctetString tmpOct(buf, length);
		gcry_free (buf);
		Util::addOctetStringToVector(tmpOct, &vec, true);
	}
	Botan::OctetString encoded(reinterpret_cast<const Botan::byte*>(&vec[0]), vec.size());
	return encoded;
}

Botan::OctetString OPake::encodeNuS(gcry_mpi_t **S, int c, int nu){
	std::vector<Botan::byte> vec;
	for (int j = 0; j < nu; ++j) {
		for(int i = 0; i < c; ++i) {
			unsigned char *buf;
			size_t length;
			gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, &length, S[j][i]);
			Botan::OctetString tmpOct(buf, length);
			gcry_free (buf);
			Util::addOctetStringToVector(tmpOct, &vec, true);
		}
	}
	Botan::OctetString encoded(reinterpret_cast<const Botan::byte*>(&vec[0]), vec.size());
	return encoded;
}

// generate the final key of OSpake
void OPake::keyGen(Botan::OctetString K, Botan::OctetString *finalK, Botan::InitializationVector *iv, std::vector<Botan::byte> sid){
	std::string forKey = "1";
	// get S as byte vector
	Botan::SecureVector<Botan::byte> sidVec(&sid[0], sid.size());
	*finalK = Botan::OctetString(PRF(K, sidVec, forKey, iv));
}

// generate server confirmation message of OSpake
void OPake::confGen(Botan::OctetString K, Botan::OctetString *conf, Botan::InitializationVector *iv, std::vector<Botan::byte> sid){
	std::string forConf = "0";
	Botan::SecureVector<Botan::byte> sidVec(&sid[0], sid.size());
	*conf = Botan::OctetString(PRF(K, sidVec, forConf, iv));
}

// simulating a keyed PRF using CBC-MAC with AES256
Botan::SecureVector<Botan::byte> OPake::PRF(Botan::OctetString k, Botan::SecureVector<Botan::byte> sid, std::string indicator, Botan::InitializationVector *iv){
	Botan::AutoSeeded_RNG rng;
	if (iv->length() == 0)
		*iv = Botan::InitializationVector(rng, 16); // a random 128-bit IV

	// CBC-MAC(AES-256) AES-256/CBC
//	Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", k, *iv, Botan::ENCRYPTION), new Botan::Hash_Filter("SHA-256"));
	Botan::Pipe pipe(new Botan::MAC_Filter("CBC-MAC(AES-256)", k));

	std::string toEnc = Botan::OctetString(sid).as_string()+indicator;
	pipe.process_msg(toEnc);

	Botan::SecureVector<Botan::byte> out = pipe.read_all(0);

	return out;
}

mk OPake::finalServerMessage(mk min){
	mk result;
	Botan::InitializationVector ivKey, ivConf;
	Botan::OctetString finalK, confVal;
	keyGen(min.k, &finalK, &ivKey, this->sid);
	confGen(min.k, &confVal, &ivConf, this->sid);
	result.k = finalK;

	// add IVs to message
	std::vector<Botan::byte> out;
	Util::addOctetStringToVector(confVal, &out, true);
	Util::addOctetStringToVector(ivKey, &out, true);
	Util::addOctetStringToVector(ivConf, &out, true);
	result.m = Botan::OctetString(reinterpret_cast<const Botan::byte*>(&out[0]), out.size());
	return result;
}

void OPake::decodeFinalMessage(message m, Botan::OctetString &ivKey, Botan::OctetString &ivConf, Botan::SecureVector<Botan::byte> &confVal){
	Botan::u32bit confLength = Botan::BigInt::decode(m.begin(), 8, Botan::BigInt::Binary).to_u32bit();
	confVal = Botan::SecureVector<Botan::byte>(m.begin()+8*sizeof(Botan::byte), confLength);

	Botan::u32bit ivLength = Botan::BigInt::decode(m.begin()+8+confLength, 8, Botan::BigInt::Binary).to_u32bit();
	ivKey = Botan::OctetString(m.begin()+2*8*sizeof(Botan::byte)+confLength, ivLength);
	ivConf = Botan::OctetString(m.begin()+3*8*sizeof(Botan::byte)+confLength+ivLength, ivLength);
}

// initializes an IHME result set S (output of IHME encode function)
// TODO: Need clean up function for S
gcry_mpi_t* OPake::createIHMEResultSet(int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	for(int k = 0; k < numPwds; k++)
		S[k] = gcry_mpi_new(0);
	return S;
}

// initializes an IHME result set S (output of IHME encode function)
// TODO: Need clean up function for S
gcry_mpi_t** OPake::createNuIHMEResultSet(int numPwds, int nu){
	gcry_mpi_t **S;
	S = (gcry_mpi_t**)calloc(nu, sizeof(gcry_mpi_t*));
	for(int k = 0; k < nu; k++) {
		S[k] = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
		for (int i=0; i < numPwds; i++) {
			S[k][i] = gcry_mpi_new(0);
		}
	}
	return S;
}

void OPake::init(std::vector<std::string> pwds, ROLE role, int c, Pake *p){
	this->c = c;
	if (role == CLIENT){
		for (int i = 0; i < c; ++i) {
			Pake *tmp = p->clone();
			this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		}
		for(int i = 0; i < c ; ++i){
			this->procs[i]->init(pwds[i], role);
		}
	} else { // there is only one instance for the server with one password
		Pake *tmp = p->clone();
		this->procs.push_back(boost::shared_ptr<Pake>(tmp));
		this->procs[0]->init(pwds[0], role);
	}
}

mk OPake::nextServer(message m, AdmissibleEncoding *ae, Botan::BigInt P, encodeServerMessage enc, int nu){
	mk result;
	Botan::OctetString messageIn;
	if (m.length() != 0){
		// get correct message first
		gcry_mpi_t p;
		Util::BigIntToMpi(&p, P);

		// only a single element in the PAKE message or is it composed?
		if (nu == 0){
			Botan::BigInt aeEncodedM = ihmeDecode(m, c, this->procs[0]->getPwd(), p);
			Botan::BigInt message = ae->decode(aeEncodedM);
			messageIn = Botan::OctetString(Botan::BigInt::encode(message));
		} else {
			Botan::OctetString aeEncodedM = nuIhmeDecode(m, c, nu, this->procs[0]->getPwd(), p);

			// now split aeEncodedM into the elements to reconstruct the original PAKE message from it
			size_t length = P.bits()/8;
			std::vector<Botan::BigInt> aeDecoded;
			int numElements = aeEncodedM.length()/length; // XXX: has to be an int, otherwise something went wrong
			for (int i = 0; i < numElements; ++i) {
				Botan::BigInt tmp = Botan::BigInt::decode(aeEncodedM.begin()+i*length, length, Botan::BigInt::Binary);
				aeDecoded.push_back(ae->decode(tmp));
			}
			messageIn = enc(aeDecoded);
		}
	} else {
		messageIn = m;
	}
	result = this->procs[0]->next(messageIn);

	if (result.k.length() != 0)
		this->keys.push_back(result.k);

	this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());
	this->sid.insert(this->sid.end(), result.m.begin(), result.m.begin()+result.m.length());

	// calculate confirmation message and real final key
	if (result.m.length() == 0 || result.k.length() != 0){
#ifdef DEBUG
		std::cout << "creating confirmation message and final key...\n";
#endif

		mk finalResult = finalServerMessage(result);

		// check whether there is a last PAKE server message or not
		if (result.m.length() == 0) {
			result = finalResult;
		} else {
			// replace key in result and append confirmation message to last message
			result.k = finalResult.k;
			Util::OctetStringConcat(result.m, finalResult.m, false);
		}

	}
	return result;
}

mk OPake::nextClient(message m, Botan::BigInt ihmeP, encodeOutgoingMessage encode, AdmissibleEncoding *ae, decodeIncommingServerMessage decode, int nu) {
	mk result;

	if (!this->finished){ // normal PAKE computations here
		// clear key vector
		this->keys.clear();
		// add incoming message to sid
		this->sid.insert(this->sid.end(), m.begin(), m.begin()+m.length());

		// construct Point structure P for IHME
		struct point P[this->c];
		for (int k = 0; k < this->c; k++)
			initpoint(&P[k]);
		int pos = 0;

		// FIXME: be able to handle less than c passwords!
		// iterate over passwords
		for (int i = 0; i < this->c; ++i) { //FIXME: incoming m could be empty!

			// call underlying PAKE
			mk piResult = this->procs[i]->next(m);

			// FIXME: choose random message otherwise!
			if (piResult.m.length() != 0) {
				// encode the client's messages (admissible encoding and everything else)
				Botan::BigInt aeEncoded = encode(piResult.m, ae, &this->finished);

				// add out to IHME structure P
				addElement(P, &pos, this->procs[i]->getPwd(), aeEncoded);
			}

			// store key for internal use
			this->keys.insert(this->keys.end(), piResult.k);
		}
		// just return the first, is not the correct one anyway
		result.k = this->keys[0];

		// we don't have a message in the last round (only confirmation and key calculation there)
		if (gcry_mpi_cmp_ui(P[0].x, 0)){
			// compute IHME structure S from P with c passwords and modulus p
			gcry_mpi_t p;
			Util::BigIntToMpi(&p, ihmeP);

			Botan::OctetString out;
			if (nu == 0) {
				gcry_mpi_t *S;
				S = createIHMEResultSet(this->c);
				interpolation_alg2(S, P, this->c, p);

				// have to encode the S as OctetString
				out = encodeS(S, this->c);
			} else {
				gcry_mpi_t **S;
				S = createNuIHMEResultSet(this->c, nu);
				v_fold_interleaving_encode(S, P, nu, this->c, p);

				// have to encode the S as OctetString
				out = encodeNuS(S, this->c, nu);
			}
			result.m = out;
			this->sid.insert(this->sid.end(), out.begin(),out.begin()+out.length());
		}
	} else { // Here Pi finished and the incoming message is the confirmation message and maybe the last server message
		// decode incoming message
		// min[0] := confirmation message, min[1] := server message or
		// min[0] := confirmation message

		message confM, min;

		if (decode != 0) {
			std::vector<message> tmp = decode(m);

			// add incoming message to sid
			this->sid.insert(this->sid.end(), tmp[1].begin(), tmp[1].begin()+tmp[1].length());

			confM = tmp[0];
			min = tmp[1];
		} else {
			confM = m;
		}


		Botan::OctetString ivKey, ivConf;
		Botan::SecureVector<Botan::byte> confVal;
		decodeFinalMessage(confM, ivKey, ivConf, confVal);

		// compute keys for Client
		for (int var = 0; var < this->c; ++var) {
			Botan::OctetString key;

			mk piResult;
			if (min.length() > 1) {
				// call underlying PAKE
				piResult = this->procs[var]->next(min);
				key = piResult.k;
			} else {
				key = this->keys[var];
			}

			// generate confirmation message for every computed key
			// only have to do this when we have a key!
			if (key.length() > 1) {
				Botan::OctetString conf;
				confGen(key, &conf, &ivConf, this->sid);

				if (conf == confVal){
#ifdef DEBUG
					std::cout << "got the key :)\n";
#endif
					keyGen(key, &result.k, &ivKey, this->sid);
					break; // XXX: we can stop when we found the correct key; Problem: Side-Channel Attacks
				}
			}
		}
	}
	return result;
}
