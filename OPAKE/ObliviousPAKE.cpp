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

Botan::OctetString OPake::nuIhmeDecode(message m, Botan::DL_Group G, int c, int nu, Botan::BigInt pwd, gcry_mpi_t p){
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
	Util::BigIntToMpi(&pwdMpi, pwd); // FIXME: do we need an admissible encoding here too?!
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

// simulating a keyed PRF as AES encryption of the input
// FIXME: How to implement PRF correct?
Botan::SecureVector<Botan::byte> OPake::PRF(Botan::OctetString k, Botan::SecureVector<Botan::byte> sid, std::string indicator, Botan::InitializationVector *iv){
	Botan::AutoSeeded_RNG rng;
	if (iv->length() == 0)
		*iv = Botan::InitializationVector(rng, 16); // a random 128-bit IV

	Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", k, *iv, Botan::ENCRYPTION), new Botan::Hash_Filter("SHA-256"));

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

void OPake::splitFinalCombinedMessage(Botan::OctetString m, Botan::OctetString &min, Botan::OctetString &conf){
	Botan::u32bit length = Botan::BigInt::decode(m.begin(), 8, Botan::BigInt::Binary).to_u32bit()+8;
	length += 16; // FIXME: have to make this length variable!!!
	Util::OctetStringSplit(m, min, conf, length);
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

mk OPake::nextServer(message m, AdmissibleEncoding *ae, Botan::BigInt P){
	mk result;
	Botan::OctetString messageIn;
	if (m.length() != 0){
		// get correct message first
		gcry_mpi_t p;
		Util::BigIntToMpi(&p, P);
		Botan::BigInt aeDecodedM = ihmeDecode(m, c, this->procs[0]->getPwd(), p);
		Botan::BigInt message = ae->decode(aeDecodedM);
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
		result = finalServerMessage(result);
	}
	return result;
}
