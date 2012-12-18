/*
 * oSpake.cpp
 *
 *  Created on: Dec 10, 2012
 *      Author: franziskus
 */

// Botan stuff
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>
using namespace Botan;

// gcrypt stuff for IHME
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <assert.h>
#include <time.h>
#include "IHME.h"
#include <math.h>

#define DEBUG 1
#define NUM 2
#define NU 2
#define BILLION 1000000000L

#include <iostream>
#include <memory>

struct z_p_star {
	BigInt p;
	BigInt a;
	BigInt g;
};

z_p_star generate_Z(DL_Group G){
	// generate p' = a*p+1
	BigInt q = G.get_q(); // 2047 bit
	bool found = false;
	BigInt a = 2; // stays 2
	AutoSeeded_RNG rng;
	BigInt pp;
	z_p_star result;
	while(!found){
		if (gcd(a, q) == 1){ // will be true first time
			pp = a*q+1;
			if (check_prime(pp, rng)){ // will be true first time
				found = true;
				result.p = pp;
				result.a = a;
				// get a generator for G=Z_p^*
				BigInt gg = BigInt::random_integer(rng, 0, pp);
				while (power_mod(gg, BigInt(2), pp) == 1 || power_mod(gg, q, pp) == 1){
					gg = BigInt::random_integer(rng, 0, pp);
				}
				result.g = gg;
			} else {
				++a;
			}
		}
	}
	return result;
}

static void print_mpi (const char *name, gcry_mpi_t a) {
	gcry_error_t err;
	unsigned char *buf;
//	int writerr = 0;

	err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, a);
//	if (err)
//		printf("gcry_mpi_aprint failed: %s\n", gcry_strerror (err));

	printf ("%s: %s\n", name, buf);
//	if (ferror (stdout))
//		writerr++;
//	if (!writerr && fflush (stdout) == EOF)
//		writerr++;
//	if (writerr)
//		printf("writing output failed\n");
	gcry_free (buf);
}

void BigIntToMpi(gcry_mpi_t *mpiResult, BigInt in){
	SecureVector<byte> tmp = BigInt::encode(in);
	*mpiResult = gcry_mpi_new(0);
	size_t nscanned;
	gcry_mpi_scan(mpiResult, GCRYMPI_FMT_USG, tmp.begin(), tmp.size(), &nscanned);

//	std::cout << "Original: " << std::hex << in << "\n";
//	print_mpi("mpi", mpiResult);
}

BigInt MpiToBigInt(gcry_mpi_t in){
	unsigned char *buf;
	gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, in);
//	std::cout << "gcry_mpi_get_nbits(in): " << ceil((double)gcry_mpi_get_nbits(in)) << "\n";
//	std::cout << "gcry_mpi_get_nbits(in)/8: " << ceil((double)gcry_mpi_get_nbits(in)/8) << "\n";
//	print_mpi("mpiToBigInt", in);
	BigInt bigIntResult = BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), BigInt::Binary);
	gcry_free (buf);

//	std::cout << "converted: " << std::hex << bigIntResult << "\n";
//	print_mpi("original mpi", in);

	return bigIntResult;
}

OctetString hashIt(std::string params, BigInt A, BigInt B, BigInt pwd, BigInt K){
	SHA_256 h;
	h.update(params);
	h.update(BigInt::encode(A));
	h.update(BigInt::encode(B));
	h.update(BigInt::encode(pwd));
	h.update(BigInt::encode(K));
	return OctetString(h.final());
}

void addElement(struct point *P, int *pos, BigInt pwd, BigInt m){
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

void iEncode(gcry_mpi_t *S, struct point *P, DL_Group G){
//	struct point P[NUM];
	int i, k;
	G.get_p();
	gcry_mpi_t p;
//	gcry_mpi_set

	gcry_check_version("1.4.1");


	p = gcry_mpi_new(0);
	gcry_mpi_set_ui(p, 44189); //23

	for(k = 0; k < NUM; k++)
		initpoint(&P[k]);

	gcry_mpi_set_ui(P[0].x, 2);
	gcry_mpi_set_ui(P[0].y, 50); // 22

	gcry_mpi_set_ui(P[1].x, 4);
	gcry_mpi_set_ui(P[1].y, 3);

	gcry_mpi_set_ui(P[2].x, 6);
	gcry_mpi_set_ui(P[2].y, 1);

	gcry_mpi_set_ui(P[3].x, 8);
	gcry_mpi_set_ui(P[3].y, 2);

	gcry_mpi_set_ui(P[4].x, 10);
	gcry_mpi_set_ui(P[4].y, 7);

	gcry_mpi_set_ui(P[5].x, 11);
	gcry_mpi_set_ui(P[5].y, 7);

	gcry_mpi_set_ui(P[6].x, 12);
	gcry_mpi_set_ui(P[6].y, 7);

//	c1 = calloc(NUM, sizeof(gcry_mpi_t));
	for(k = 0; k < NUM; k++)
		S[k] = gcry_mpi_new(0);

	interpolation_alg2(S, P, NUM, p);

	// Test Decoding
//	test1 = gcry_mpi_new(0);
//	decode(test1,c1,P[0].x,NUM,p);
	//	print_mpi("P[0].y", P[0].y);
	//	print_mpi("dec", test1);
	//	decode(test1,c1,P[1].x,NUM,p);
	//	print_mpi("P[1].y", P[1].y);
	//	print_mpi("dec", test1);
	//	decode(test1,c1,P[2].x,NUM,p);
	//	print_mpi("P[2].y", P[2].y);
	//	print_mpi("dec", test1);
	//	decode(test1,c1,P[0].x,NUM,p);

//	check_1 = gcry_mpi_cmp(P[0].y,test1);
//	if (check_1 == 0) {
//		printf("Encode/Decode-Test successful!\n");
//	} else {
//		printf("Encode/Decode-Test NOT successful!\n");
//	}
}

BigInt pwdToBigInt(std::string pwd){
	const byte* pwdB = (byte*)&pwd[0];
	return BigInt::decode(pwdB, pwd.length(), BigInt::Binary);
}

BigInt createMessate(DH_PrivateKey privateKey, BigInt pwd, DL_Group G, BigInt M){
	return (privateKey.get_y()*(power_mod(M, pwd, G.get_p()))) % G.get_p();
}

/*
 * The admissible encoding function for one group element of G
 */
BigInt aEncode(z_p_star z, DL_Group G, BigInt in){
	AutoSeeded_RNG rng;
	BigInt gpowq = power_mod(z.g, G.get_q(), z.p);
	BigInt r = BigInt::random_integer(rng, 0, z.a);
	BigInt gpowqr = power_mod(gpowq, r, z.p);
	BigInt mpowainv = power_mod(in, inverse_mod(z.a, G.get_q()), z.p);
	return (gpowqr*mpowainv) % z.p;
}

BigInt aDecode(z_p_star z, DL_Group G, BigInt in){
	return power_mod(in, z.a, G.get_p());
}

gcry_mpi_t* createIHMEResultSet(){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(NUM, sizeof(gcry_mpi_t));
	for(int k = 0; k < NUM; k++)
		S[k] = gcry_mpi_new(0);
	return S;
}

SecureVector<byte> PRF(OctetString k, SecureVector<byte> sid, std::string indicator, InitializationVector *iv){
	AutoSeeded_RNG rng;
	SymmetricKey key = k; // use the BigInt as 256-bit key
	std::cout << "iv.length: " << iv->length() <<"\n";
	if (iv->length() == 0)
		*iv = InitializationVector(rng, 16); // a random 128-bit IV

	Pipe pipe(get_cipher("AES-256/CBC", key, *iv, ENCRYPTION));

	std::string toEnc = OctetString(sid).as_string()+indicator;
//	std::cout << "toEnc: " << toEnc << "\n";
	pipe.process_msg(toEnc);

	SecureVector<byte> out = pipe.read_all(0);
//	std::cout << "encrypted: " << OctetString(out).as_string() << "\n";

	return out;

	// FIXME: testing decryption here
//	Pipe pipe2(get_cipher("AES-256/CBC", key, iv, DECRYPTION));
//
//	pipe2.process_msg(out);
//
//	std::string decrypted = pipe2.read_all_as_string(0);
//	std::cout << "dec: " << decrypted << "\n";
}

void print_vector(std::vector<byte> *vec){
	for(int i = 0; i < vec->size();i++){
		printf("%02X", vec->at(i));
	}
}

std::vector<byte> getSbuf(gcry_mpi_t *S){
	unsigned char *buffer; size_t l; std::vector<byte> Sbuf;
	for (int i = 0; i < NUM; ++i) {
		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &l, S[i]);
		Sbuf.insert(Sbuf.end(), buffer, buffer+l);
	}
	return Sbuf;
}

void keyGen(OctetString B, std::vector<byte> Sbuf, OctetString K, OctetString *finalK, InitializationVector *iv){
//	std::string forConf = "0";
	std::string forKey = "1";
//	SecureVector<byte> sidB = BigInt::encode(B);
	// get S as byte vector
//	unsigned char *buffer; size_t l; std::vector<byte> Sbuf;
//	for (int i = 0; i < NUM; ++i) {
//		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &l, S[i]);
//		Sbuf.insert(Sbuf.end(), buffer, buffer+l);
//	}
	//		print_mpi("S[0]", S[0]);
	//		print_mpi("S[1]", S[1]);
	//		SecureVector<byte> sid = BigInt::encode(S);
	// build sid := S||B
//	OctetString tmpSid(sidB);
	//		std::cout << "B: " << tmpSid.as_string() << "\n";
	Sbuf.insert(Sbuf.end(), B.begin(), B.begin()+B.length());
	//		std::cout << "---This is It: "; print_vector(&Sbuf); std::cout << "\n";
	//		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
	SecureVector<byte> sid(&(Sbuf[0]), Sbuf.size());
	//		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
//	*conf = PRF(K, sid, forConf, iv);
	*finalK = OctetString(PRF(K, sid, forKey, iv));
}

void confGen(OctetString B, std::vector<byte> Sbuf, OctetString K, SecureVector<byte> *conf, InitializationVector *iv){
	std::string forConf = "0";
//	std::string forKey = "1";
	//	SecureVector<byte> sidB = BigInt::encode(B);
	// get S as byte vector
	//	unsigned char *buffer; size_t l; std::vector<byte> Sbuf;
	//	for (int i = 0; i < NUM; ++i) {
	//		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &l, S[i]);
	//		Sbuf.insert(Sbuf.end(), buffer, buffer+l);
	//	}
	//		print_mpi("S[0]", S[0]);
	//		print_mpi("S[1]", S[1]);
	//		SecureVector<byte> sid = BigInt::encode(S);
	// build sid := S||B
	//	OctetString tmpSid(sidB);
	//		std::cout << "B: " << tmpSid.as_string() << "\n";
	Sbuf.insert(Sbuf.end(), B.begin(), B.begin()+B.length());
	//		std::cout << "---This is It: "; print_vector(&Sbuf); std::cout << "\n";
	//		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
	SecureVector<byte> sid(&(Sbuf[0]), Sbuf.size());
	//		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
	*conf = PRF(K, sid, forConf, iv);
}

BigInt computeKey(BigInt publicValue, BigInt pwd, BigInt publicKey, DH_PrivateKey privateKey, DL_Group G){
	BigInt NPW = power_mod(publicValue, pwd, G.get_p());
	return power_mod(publicKey*(inverse_mod(NPW, G.get_p())), privateKey.get_x(), G.get_p());
}

int main()
{
	try
	{
		LibraryInitializer init;
		AutoSeeded_RNG rng;
		struct timespec start, stop;
		double accum, accumA;
		clock_t clk_tmp;


		// Alice and Bob agree on a DH domain to use
		DL_Group G("modp/ietf/2048");

		// generate SPAKE public variables (M,N)
		BigInt tmp = BigInt(rng, (size_t)1024);
		BigInt M = power_mod(G.get_g(), tmp, G.get_p());

		tmp = BigInt(rng, (size_t)1024);
		BigInt N = power_mod(G.get_g(), tmp, G.get_p());

		const std::string session_param = "Alice and Bob's shared session parameter";

		// Alice creates a DH key
		clock_gettime(CLOCK_REALTIME, &start);
		DH_PrivateKey private_a(rng, G);

		// Alice sends to Bob her public key and a session parameter
		// include password here
		BigInt pwd1Num = pwdToBigInt("Password1");
		BigInt pwd2Num = pwdToBigInt("Password2");
		
		BigInt public_a1BigInt = createMessate(private_a, pwd1Num, G, M);
		BigInt public_a2BigInt = createMessate(private_a, pwd2Num, G, M);

		///////////////////////////////////////////////////////////////////
		// XXX: here the interesting stuff happens.....

		// generate admissible encoding parameters
		z_p_star z = generate_Z(G);

		// encode the client's (Alice) messages
		BigInt encoded_public_A1 = aEncode(z, G, public_a1BigInt);
		BigInt encoded_public_A2 = aEncode(z, G, public_a2BigInt);

		// add IHME to the admissible encoded values
		struct point P[NUM];
		gcry_mpi_t *S;
		for (int k = 0; k < NUM; k++)
			initpoint(&P[k]);
		int pos = 0;
		addElement(P, &pos, pwd1Num, encoded_public_A1);
		addElement(P, &pos, pwd2Num, encoded_public_A2);
		S = createIHMEResultSet();
		gcry_mpi_t p;
		BigIntToMpi(&p, G.get_p());
		interpolation_alg2(S, P, NUM, p);
		//XXX: Alice outputs S and sends it to Bob /////////////////////

		clock_gettime(CLOCK_REALTIME, &stop);
		accumA = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;


		///////////////// BOB //////////////////////////////////////

		// Bob creates a key with a matching group
		clock_gettime(CLOCK_REALTIME, &start);
		DH_PrivateKey private_b(rng, G);

		// Bob sends his public key to Alice
		// include password here
		BigInt public_b1BigInt = createMessate(private_b, pwd1Num, G, N); //private_b.get_y()*(power_mod(N, pwd1Num, G.get_p()));

		// decode it again (Bob does)
		// IHME decode
		gcry_mpi_t encoded_public_A_MPI;
		encoded_public_A_MPI = gcry_mpi_new(0);
		gcry_mpi_t pwd1NumMPI;
		BigIntToMpi(&pwd1NumMPI, pwd1Num);
		decode(encoded_public_A_MPI,S,pwd1NumMPI,NUM,p);
		BigInt aEncodedMessageFromAlice = MpiToBigInt(encoded_public_A_MPI);

		// admissible decode
		BigInt bobs_public_A = aDecode(z, G, aEncodedMessageFromAlice); //power_mod(encoded_public_A1, z.a, G.get_p());

		// compute k for bob
//		BigInt MPW = power_mod(M, pwd1Num, G.get_p());
//		BigInt KB = power_mod(bobs_public_A*(inverse_mod(MPW, G.get_p())), private_b.get_x(), G.get_p());
		BigInt KB = computeKey(M, pwd1Num, bobs_public_A, private_b, G);

		// Bob calculates the his keys:
		OctetString bob_key = hashIt(session_param, bobs_public_A, public_b1BigInt, pwd1Num, KB);

		// bob calculates hash value for confirmation
//		std::string forConf = "0";
//		std::string forKey = "1";
//		SecureVector<byte> sidB = BigInt::encode(public_b1BigInt);
//		// get S as byte vector
//		unsigned char *buffer; size_t l; std::vector<byte> Sbuf;
//		for (int i = 0; i < NUM; ++i) {
//			gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &l, S[i]);
//			Sbuf.insert(Sbuf.end(), buffer, buffer+l);
//		}
////		print_mpi("S[0]", S[0]);
////		print_mpi("S[1]", S[1]);
////		SecureVector<byte> sid = BigInt::encode(S);
//		// build sid := S||B
//		OctetString tmpSid(sidB);
////		std::cout << "B: " << tmpSid.as_string() << "\n";
//		Sbuf.insert(Sbuf.end(), tmpSid.begin(), tmpSid.begin()+tmpSid.length());
////		std::cout << "---This is It: "; print_vector(&Sbuf); std::cout << "\n";
////		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
//		SecureVector<byte> sid(&(Sbuf[0]), Sbuf.size());
////		std::cout << "sid: " << OctetString(sid).as_string() << "\n";
//		SecureVector<byte> conf = PRF(bob_key, sid, forConf);
//		OctetString bob_key_2 = OctetString(PRF(bob_key, sid, forKey));

		SecureVector<byte> confVal;
		OctetString bobFinalK;
		std::vector<byte> Sbuf = getSbuf(S);
		OctetString public_A(BigInt::encode(bobs_public_A));
		InitializationVector ivKey, ivConf;
		keyGen(public_A, Sbuf, bob_key, &bobFinalK, &ivKey);
		confGen(public_A, Sbuf, bob_key, &confVal, &ivConf);
		std::cout << "confVal: " << OctetString(confVal).as_string() << "\n";

		clock_gettime(CLOCK_REALTIME, &stop);
		accum = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
		printf("TIMING: Bob: %lf sec\n", accum);
		///////////////////////////////////////////////////////////////////////////////////////////////////

		// XXX: Second part Alice: compute keys ///////////////////////
		clock_gettime(CLOCK_REALTIME, &start);

		// Now Alice performs the key agreement operation
		// compute keys for alice
//		BigInt NPW = power_mod(N, pwd1Num, G.get_p());
//		BigInt KA = power_mod(public_b1BigInt*(inverse_mod(NPW, G.get_p())), private_a.get_x(), G.get_p());
		BigInt KA1 = computeKey(N, pwd1Num, public_b1BigInt, private_a, G);
		BigInt KA2 = computeKey(N, pwd2Num, public_b1BigInt, private_a, G);
		OctetString alice_key1 = hashIt(session_param, public_a1BigInt, public_b1BigInt, pwd1Num, KA1);
		OctetString alice_key2 = hashIt(session_param, public_a1BigInt, public_b1BigInt, pwd1Num, KA2);

		// check confirmation value and get correct key
		SecureVector<byte> confKA1, confKA2;
//		OctetString finalKA1, finalKA2;
		std::vector<byte> SbufA = getSbuf(S);
		OctetString public_B(BigInt::encode(public_b1BigInt));
		confGen(public_B, SbufA, alice_key1, &confKA1, &ivConf);
		std::cout << "confKA1: " << OctetString(confKA1).as_string() << "\n";
		confGen(public_B, SbufA, alice_key1, &confKA2, &ivConf);
		std::cout << "confKA2: " << OctetString(confKA2).as_string() << "\n";
		OctetString alice_key;
		if (confKA1 == confVal){
			keyGen(public_B, SbufA, alice_key1, &alice_key, &ivKey);
		}
		else if (confKA2 == confVal){
			keyGen(public_B, SbufA, alice_key2, &alice_key, &ivKey);
		}
		else
			alice_key = OctetString("00");


		clock_gettime(CLOCK_REALTIME, &stop);
		accumA += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
		printf("TIMING: Alice: %lf sec\n", accumA);

		if(alice_key == bob_key)
		{
			std::cout << "The two keys matched, everything worked\n";
			std::cout << "The shared key was: " << alice_key.as_string() << "\n";
		}
		else
		{
			std::cout << "The two keys didn't match! Hmmm...\n";
			std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
			std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
		}

	}
	catch(std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return 1;
	}
	return 0;
}
