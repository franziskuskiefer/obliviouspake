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

int main()
{
	try
	{
		LibraryInitializer init;
		AutoSeeded_RNG rng;
		clock_t clk_tmp;

		// Alice and Bob agree on a DH domain to use
		DL_Group G("modp/ietf/2048");

		// generate SPAKE public variables (M,N)
		BigInt tmp = BigInt(rng, (size_t)1024);
		BigInt M = power_mod(G.get_g(), tmp, G.get_p());

		tmp = BigInt(rng, (size_t)1024);
		BigInt N = power_mod(G.get_g(), tmp, G.get_p());

		// Alice creates a DH key
		clk_tmp = clock();
		DH_PrivateKey private_a(rng, G);
		clk_tmp = clock() - clk_tmp;
		printf("Dauer std IHME Encode [ms]: %f\n", (double) (clk_tmp/(CLOCKS_PER_SEC/1000)));

		// Bob creates a key with a matching group
		DH_PrivateKey private_b(rng, G);

		// Alice sends to Bob her public key and a session parameter
		// include password here
		BigInt pwd1Num = pwdToBigInt("Password1");
		BigInt pwd2Num = pwdToBigInt("Password2");
		
		const std::string session_param = "Alice and Bob's shared session parameter";

		BigInt public_a1BigInt = createMessate(private_a, pwd1Num, G, M); //(private_a.get_y()*(power_mod(M, pwd1Num, G.get_p()))) % G.get_p();
		BigInt public_a2BigInt = createMessate(private_a, pwd2Num, G, M);

		// Bob sends his public key to Alice
		// include password here
		BigInt public_b1BigInt = createMessate(private_b, pwd1Num, G, N); //private_b.get_y()*(power_mod(N, pwd1Num, G.get_p()));

		///////////////////////////////////////////////////////////////////////////////////////////////////
		// XXX: here the interesting stuff happens.....

		// generate admissible encoding parameters
		z_p_star z = generate_Z(G);

		// encode the client's (Alice) messages
		BigInt encoded_public_A1 = aEncode(z, G, public_a1BigInt); //(gpowqr*mpowainv) % z.p;
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
//		print_mpi("P[0].x", P[0].x);
//		print_mpi("P[0].y", P[0].y);
//		print_mpi("P[1].x", P[1].x);
//		print_mpi("P[1].y", P[1].y);
//		print_mpi("p", p);
		interpolation_alg2(S, P, NUM, p);

		// decode it again (Bob does)
		// IHME decode
		gcry_mpi_t encoded_public_A_MPI;
		encoded_public_A_MPI = gcry_mpi_new(0);
		gcry_mpi_t pwd1NumMPI;
		BigIntToMpi(&pwd1NumMPI, pwd1Num);
//		print_mpi("S[0]", S[0]);
//		print_mpi("S[1]", S[1]);
		decode(encoded_public_A_MPI,S,pwd1NumMPI,NUM,p);
//		print_mpi("encoded_public_A_MPI", encoded_public_A_MPI);
		BigInt aEncodedMessageFromAlice = MpiToBigInt(encoded_public_A_MPI);

		// admissible decode
		BigInt bobs_public_A = aDecode(z, G, aEncodedMessageFromAlice); //power_mod(encoded_public_A1, z.a, G.get_p());
		///////////////////////////////////////////////////////////////////////////////////////////////////

		// compute k for alice
		BigInt NPW = power_mod(N, pwd1Num, G.get_p());
		BigInt KA = power_mod(public_b1BigInt*(inverse_mod(NPW, G.get_p())), private_a.get_x(), G.get_p());

		// compute k for bob
		BigInt MPW = power_mod(M, pwd1Num, G.get_p());
		BigInt KB = power_mod(bobs_public_A*(inverse_mod(MPW, G.get_p())), private_b.get_x(), G.get_p());


		// Now Alice performs the key agreement operation
		OctetString alice_key = hashIt(session_param, public_a1BigInt, public_b1BigInt, pwd1Num, KA);

		// Bob does the same:
		OctetString bob_key = hashIt(session_param, bobs_public_A, public_b1BigInt, pwd1Num, KB);

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
