///*
// * oSpake.cpp
// *
// *  Created on: Dec 10, 2012
// *      Author: franziskus
// */
//
//// Botan stuff
//#include <botan/botan.h>
//#include <botan/dh.h>
//#include <botan/pubkey.h>
//#include <botan/sha2_32.h>
//using namespace Botan;
//
//// gcrypt stuff for IHME
//#include <stdio.h>
//#include <stdlib.h>
//#include <gcrypt.h>
//#include <assert.h>
//#include <time.h>
//#include "IHME.h"
//#include <math.h>
//
//#define DEBUG 1
//#define NUM 2
//#define NU 2
//#define BILLION 1000000000L
//
//#include <iostream>
//#include <memory>
//
//struct z_p_star {
//	BigInt p;
//	BigInt a;
//	BigInt g;
//};
//
//z_p_star generate_Z(DL_Group G){
//	// generate p' = a*p+1
//	BigInt q = G.get_q(); // 2047 bit
//	bool found = false;
//	BigInt a = 2; // stays 2
//	AutoSeeded_RNG rng;
//	BigInt pp;
//	z_p_star result;
//	while(!found){
//		if (gcd(a, q) == 1){ // will be true first time
//			pp = a*q+1;
//			if (check_prime(pp, rng)){ // will be true first time
//				found = true;
//				result.p = pp;
//				result.a = a;
//				// get a generator for G=Z_p^*
//				BigInt gg = BigInt::random_integer(rng, 0, pp);
//				while (power_mod(gg, BigInt(2), pp) == 1 || power_mod(gg, q, pp) == 1){
//					gg = BigInt::random_integer(rng, 0, pp);
//				}
//				result.g = gg;
//			} else {
//				++a;
//			}
//		}
//	}
//	return result;
//}
//
//static void print_mpi (const char *name, gcry_mpi_t a) {
//	gcry_error_t err;
//	unsigned char *buf;
//
//	err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, a);
//
//	printf ("%s: %s\n", name, buf);
//	gcry_free (buf);
//}
//
//void BigIntToMpi(gcry_mpi_t *mpiResult, BigInt in){
//	SecureVector<byte> tmp = BigInt::encode(in);
//	*mpiResult = gcry_mpi_new(0);
//	size_t nscanned;
//	gcry_mpi_scan(mpiResult, GCRYMPI_FMT_USG, tmp.begin(), tmp.size(), &nscanned);
//}
//
//BigInt MpiToBigInt(gcry_mpi_t in){
//	unsigned char *buf;
//	gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, in);
//	BigInt bigIntResult = BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), BigInt::Binary);
//	gcry_free (buf);
//
//	return bigIntResult;
//}
//
//OctetString hashIt(std::string params, BigInt A, BigInt B, BigInt pwd, BigInt K){
//	SHA_256 h;
//	h.update(params);
//	h.update(BigInt::encode(A));
//	h.update(BigInt::encode(B));
//	h.update(BigInt::encode(pwd));
//	h.update(BigInt::encode(K));
//	return OctetString(h.final());
//}
//
//void addElement(struct point *P, int *pos, BigInt pwd, BigInt m){
//	// convert BigInts to MPIs
//	gcry_mpi_t pwdMpi;
//	BigIntToMpi(&pwdMpi, pwd);
//	gcry_mpi_t mMpi;
//	BigIntToMpi(&mMpi, m);
//
//	// add (pwd, m) to P
//	P[*pos].x = pwdMpi;
//	P[*pos].y = mMpi;
//	++*pos;
//}
//
//BigInt pwdToBigInt(std::string pwd){
//	const byte* pwdB = (byte*)&pwd[0];
//	return BigInt::decode(pwdB, pwd.length(), BigInt::Binary);
//}
//
//BigInt createMessate(DH_PrivateKey privateKey, BigInt pwd, DL_Group G, BigInt M){
//	return (privateKey.get_y()*(power_mod(M, pwd, G.get_p()))) % G.get_p();
//}
//
///*
// * The admissible encoding function for one group element of G
// */
//BigInt aEncode(z_p_star z, DL_Group G, BigInt in){
//	AutoSeeded_RNG rng;
//	BigInt gpowq = power_mod(z.g, G.get_q(), z.p);
//	BigInt r = BigInt::random_integer(rng, 0, z.a);
//	BigInt gpowqr = power_mod(gpowq, r, z.p);
//	BigInt mpowainv = power_mod(in, inverse_mod(z.a, G.get_q()), z.p);
//	return (gpowqr*mpowainv) % z.p;
//}
//
//BigInt aDecode(z_p_star z, DL_Group G, BigInt in){
//	return power_mod(in, z.a, G.get_p());
//}
//
//gcry_mpi_t* createIHMEResultSet(){
//	gcry_mpi_t *S;
//	S = (gcry_mpi_t*)calloc(NUM, sizeof(gcry_mpi_t));
//	for(int k = 0; k < NUM; k++)
//		S[k] = gcry_mpi_new(0);
//	return S;
//}
//
//SecureVector<byte> PRF(OctetString k, SecureVector<byte> sid, std::string indicator){
//	AutoSeeded_RNG rng;
//	SymmetricKey key = k; // use the BigInt as 256-bit key
//	InitializationVector iv(rng, 16); // a random 128-bit IV
//
//	Pipe pipe(get_cipher("AES-256/CBC", key, iv, ENCRYPTION));
//
//	std::string toEnc = OctetString(sid).as_string()+indicator;
//	pipe.process_msg(toEnc);
//
//	SecureVector<byte> out = pipe.read_all(0);
//	return out;
//}
//
//int main()
//{
//	try
//	{
//		LibraryInitializer init;
//		AutoSeeded_RNG rng;
//		struct timespec start, stop;
//		double accum, accumA;
//		clock_t clk_tmp;
//
//
//		// Alice and Bob agree on a DH domain to use
//		DL_Group G("modp/ietf/2048");
//
//		// generate SPAKE public variables (M,N)
//		BigInt tmp = BigInt(rng, (size_t)1024);
//		BigInt M = power_mod(G.get_g(), tmp, G.get_p());
//
//		tmp = BigInt(rng, (size_t)1024);
//		BigInt N = power_mod(G.get_g(), tmp, G.get_p());
//
//		const std::string session_param = "Alice and Bob's shared session parameter";
//
//		// Alice creates a DH key
//		clock_gettime(CLOCK_REALTIME, &start);
//		DH_PrivateKey private_a(rng, G);
//
//		// Alice sends to Bob her public key and a session parameter
//		// include password here
//		BigInt pwdNum = pwdToBigInt("Password1");
//
//		BigInt public_aBigInt = createMessate(private_a, pwdNum, G, M);
//
//		clock_gettime(CLOCK_REALTIME, &stop);
//		accumA = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
//
//
//		///////////////// BOB //////////////////////////////////////
//
//		// Bob creates a key with a matching group
//		clock_gettime(CLOCK_REALTIME, &start);
//		DH_PrivateKey private_b(rng, G);
//
//		// Bob sends his public key to Alice
//		// include password here
//		BigInt public_bBigInt = createMessate(private_b, pwdNum, G, N);
//
//		// compute k for bob
//		BigInt MPW = power_mod(M, pwdNum, G.get_p());
//		BigInt KB = power_mod(public_aBigInt*(inverse_mod(MPW, G.get_p())), private_b.get_x(), G.get_p());
//
//		// Bob calculates the his keys:
//		OctetString bob_key = hashIt(session_param, public_aBigInt, public_bBigInt, pwdNum, KB);
//
//		clock_gettime(CLOCK_REALTIME, &stop);
//		accum = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
//		printf("TIMING: Bob: %lf sec\n", accum);
//		///////////////////////////////////////////////////////////////////////////////////////////////////
//
//		// XXX: Second part Alice: compute keys ///////////////////////
//		clock_gettime(CLOCK_REALTIME, &start);
//
//		// compute k for alice
//		BigInt NPW = power_mod(N, pwdNum, G.get_p());
//		BigInt KA = power_mod(public_bBigInt*(inverse_mod(NPW, G.get_p())), private_a.get_x(), G.get_p());
//
//		// Now Alice performs the key agreement operation
//		OctetString alice_key = hashIt(session_param, public_aBigInt, public_bBigInt, pwdNum, KA);
//
//		clock_gettime(CLOCK_REALTIME, &stop);
//		accumA += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
//		printf("TIMING: Alice: %lf sec\n", accumA);
//
//		if(alice_key == bob_key)
//		{
//			std::cout << "The two keys matched, everything worked\n";
//			std::cout << "The shared key was: " << alice_key.as_string() << "\n";
//		}
//		else
//		{
//			std::cout << "The two keys didn't match! Hmmm...\n";
//			std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
//			std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
//		}
//
//	}
//	catch(std::exception& e)
//	{
//		std::cout << e.what() << std::endl;
//		return 1;
//	}
//	return 0;
//}
