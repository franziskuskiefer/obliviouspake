/*
 * O-SPAKE.cpp
 *
 *  Created on: Jan 14, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"
#include "../AdmissibleEncoding/PrimeGroupAE.h"

// utility function for mpi printing
static void print_mpi (const char *name, gcry_mpi_t a) {
	unsigned char *buf;

	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, a);

	printf ("%s: %s\n", name, buf);
	gcry_free (buf);
}

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

// utility function to convert a Botan BigInt to a gcrypt mpi
void BigIntToMpi(gcry_mpi_t *mpiResult, Botan::BigInt in){
	Botan::SecureVector<Botan::byte> tmp = Botan::BigInt::encode(in);
	*mpiResult = gcry_mpi_new(0);
	size_t nscanned;
	gcry_mpi_scan(mpiResult, GCRYMPI_FMT_USG, tmp.begin(), tmp.size(), &nscanned);
}

// utility function to convert an OctetString to a gcrypt mpi
gcry_mpi_t* OSpake::MessageToS(Botan::OctetString in, int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	size_t nscanned;
	Botan::u32bit elementLength = 0;
	for(int k = 0; k < numPwds; k++){
		S[k] = gcry_mpi_new(0);
		elementLength = Botan::BigInt::decode(in.begin()+k*(8+elementLength), 8, Botan::BigInt::Binary).to_u32bit();
		gcry_mpi_scan(&(S[k]), GCRYMPI_FMT_USG, in.begin()+(k+1)*8*sizeof(Botan::byte)+k*elementLength, elementLength, &nscanned);
	}
	return S;
}

// initializes an IHME result set S (output of IHME encode function)
gcry_mpi_t* createIHMEResultSet(int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	for(int k = 0; k < numPwds; k++)
		S[k] = gcry_mpi_new(0);
	return S;
}

// utility function to convert a gcrypt mpi to a Botan BigInt
Botan::BigInt OSpake::MpiToBigInt(gcry_mpi_t in){
	unsigned char *buf;
	gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, in);
	Botan::BigInt bigIntResult = Botan::BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), Botan::BigInt::Binary);
	gcry_free (buf);

	return bigIntResult;
}

Botan::BigInt OSpake::ihmeDecode(message m){
	gcry_mpi_t p;
	BigIntToMpi(&p, this->G.get_p());
	// get message from m to S
	gcry_mpi_t *S = MessageToS(m, this->c);
	// IHME decode
	gcry_mpi_t encoded_public_A_MPI, serverPwdNumMPI;
	BigIntToMpi(&serverPwdNumMPI, this->procs[0]->getPwd());
	encoded_public_A_MPI = gcry_mpi_new(0);
	decode(encoded_public_A_MPI,S,serverPwdNumMPI,this->c,p);
	return MpiToBigInt(encoded_public_A_MPI);
}

// add an element to the IHME encode input structure P
void OSpake::addElement(struct point *P, int *pos, Botan::BigInt pwd, Botan::BigInt m){
	// convert BigInts to MPIs
	gcry_mpi_t pwdMpi;
	BigIntToMpi(&pwdMpi, pwd);
	gcry_mpi_t mMpi;
	BigIntToMpi(&mMpi, m);

	// add (pwd, m) to P
	P[*pos].x = pwdMpi;
	P[*pos].y = mMpi;
	++*pos;
}

void OSpake::addOctetString(Botan::OctetString toAdd, std::vector<Botan::byte> *vec) {
	Botan::SecureVector<Botan::byte> in(toAdd.begin(), toAdd.length());
	size_t size = in.size();
	for(size_t j = 0; j != sizeof(size_t); j++){
		vec->push_back(Botan::get_byte(j, size));
	}
	vec->insert(vec->end(), in.begin(), in.begin()+size);
}

Botan::OctetString OSpake::encodeS(gcry_mpi_t *S){
	std::vector<Botan::byte> vec;
	for(int i = 0; i < this->c; ++i) {
		unsigned char *buf;
		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, S[i]);
		Botan::OctetString tmpOct(buf, ceil((double)gcry_mpi_get_nbits(S[i])/8));
//		Botan::BigInt bigIntResult = Botan::BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), Botan::BigInt::Binary);
//		print_mpi("tmpMpi", S[i]);
//		std::cout << "tmpOct: " << tmpOct.as_string() << "\n";
		gcry_free (buf);
		addOctetString(tmpOct, &vec);
	}
	Botan::OctetString encoded(reinterpret_cast<const Botan::byte*>(&vec[0]), vec.size());
	return encoded;
}

// simulating a keyed PRF as AES encryption of the input
// FIXME: How to implement PRF correct?
Botan::SecureVector<Botan::byte> PRF(Botan::OctetString k, Botan::SecureVector<Botan::byte> sid, std::string indicator, Botan::InitializationVector *iv){
	Botan::AutoSeeded_RNG rng;
	if (iv->length() == 0)
		*iv = Botan::InitializationVector(rng, 16); // a random 128-bit IV

	Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", k, *iv, Botan::ENCRYPTION), new Botan::Hash_Filter("SHA-256"));

	std::string toEnc = Botan::OctetString(sid).as_string()+indicator;
	pipe.process_msg(toEnc);

	Botan::SecureVector<Botan::byte> out = pipe.read_all(0);

	return out;
}

// generate the final key of OSpake
void OSpake::keyGen(Botan::OctetString K, Botan::OctetString *finalK, Botan::InitializationVector *iv){
	std::string forKey = "1";
	// get S as byte vector
	Botan::SecureVector<Botan::byte> sid(&this->sid[0], this->sid.size());
	*finalK = Botan::OctetString(PRF(K, sid, forKey, iv));
}

// generate server confirmation message of OSpake
void OSpake::confGen(Botan::OctetString K, Botan::OctetString *conf, Botan::InitializationVector *iv){
	std::string forConf = "0";
	Botan::SecureVector<Botan::byte> sid(&this->sid[0], this->sid.size());
//	std::cout << "sid: " << Botan::OctetString(sid).as_string() << "\n";
	*conf = Botan::OctetString(PRF(K, sid, forConf, iv));
}

mk OSpake::next(message m) {
	mk result;
	std::cout << "--------------------- " << (this->procs[0]->getR() ? "Client" : "Server") << "---------------------\n";
	if (this->procs[0]->getR() == SERVER) {
		Botan::OctetString messageIn;
		if (m.length() != 0){
			// get correct message first
			PrimeGroupAE ae(&this->G);
			Botan::BigInt aeDecodedM = ihmeDecode(m);
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
			keyGen(result.k, &finalK, &ivKey);
			confGen(result.k, &result.m, &ivConf);
			result.k = finalK;

			// add IVs to message
			std::vector<Botan::byte> out;
			addOctetString(result.m, &out);
			addOctetString(ivKey, &out);
			addOctetString(ivConf, &out);
			result.m = Botan::OctetString(reinterpret_cast<const Botan::byte*>(&out[0]), out.size());
//			std::cout << "m(conf): " << result.m.as_string() << "\n";
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
//				std::cout << "i: " << i << "\n";
//				std::cout << "incoming m (client): " << m.as_string() << std::endl;
				mk piResult = this->procs[i]->next(m);
//				std::cout << "fuuM: " << piResult.m.as_string() << std::endl;
//				std::cout << "fuuK: " << piResult.k.as_string() << std::endl;
				if (piResult.m.length() == 0) {// there is no message anymore.... stop the bloody protocol
					// do not handle empty messages
					// FIXME: do we have to use random messages here?
					this->finished = true;
				} else { // only if there is really a message from Pi.next, we have to process it
					// encode the client's (Alice) messages (admissible encoding)
					PrimeGroupAE ae(&this->G);
					Botan::BigInt out = Botan::BigInt("0x"+piResult.m.as_string()); // FIXME: get BigInt direct from Pi!
//					std::cout << "m(Client): " << out << "\n";

					// add admissible encoding
					Botan::BigInt aeEncoded = ae.encode(out);
//					std::cout << "aeEncoded: " << std::hex << aeEncoded << "\n";

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
				BigIntToMpi(&p, this->G.get_p());
				gcry_mpi_t *S;
				S = createIHMEResultSet(this->c);
				interpolation_alg2(S, P, this->c, p);

				// have to encode the S as OctetString
				Botan::OctetString out = encodeS(S);
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
//				std::cout << "key: " << this->keys[var].as_string() << std::endl;
				confGen(this->keys[var], &conf, &ivConf);

//				std::cout << "confVal: " << Botan::OctetString(confVal).as_string() << std::endl;
//				std::cout << "conf: " << conf.as_string() << std::endl;
//				std::cout << "ivConf: " << ivConf.as_string() << std::endl;

				if (conf == Botan::OctetString(confVal)){
					std::cout << "got the key :)\n";
					keyGen(this->keys[var], &result.k, &ivKey);
					break; // XXX: we can stop when we found the correct key; Problem: Side-Channel Attacks
				}
			}
		}
	}
	return result;
}

