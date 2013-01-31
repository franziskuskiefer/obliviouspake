/*
 * oSpake.cpp
 *
 *  Created on: Dec 10, 2012
 *      Author: franziskus
 */

// TODO: Header ausmisten
// TODO: Hash PRF input

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
#define NU 2
#define BILLION 1000000000L

#include <iostream>
#include <memory>

// Structure to store necessary parameters of Z*_p
struct z_p_star {
	BigInt p;
	BigInt a;
	BigInt g;
};

// generate the z_p_star structure for a DL group G
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

// utility function for mpi printing
static void print_mpi (const char *name, gcry_mpi_t a) {
	unsigned char *buf;

	gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, NULL, a);

	printf ("%s: %s\n", name, buf);
	gcry_free (buf);
}

// utility function to convert a Botan BigInt to a gcrypt mpi
void BigIntToMpi(gcry_mpi_t *mpiResult, BigInt in){
	SecureVector<byte> tmp = BigInt::encode(in);
	*mpiResult = gcry_mpi_new(0);
	size_t nscanned;
	gcry_mpi_scan(mpiResult, GCRYMPI_FMT_USG, tmp.begin(), tmp.size(), &nscanned);
}

// utility function to convert a gcrypt mpi to a Botan BigInt
BigInt MpiToBigInt(gcry_mpi_t in){
	unsigned char *buf;
	gcry_mpi_aprint (GCRYMPI_FMT_USG, &buf, NULL, in);
	BigInt bigIntResult = BigInt::decode(buf, ceil((double)gcry_mpi_get_nbits(in)/8), BigInt::Binary);
	gcry_free (buf);

	return bigIntResult;
}

// key generation hashing with SHA 256
OctetString hashIt(std::string params, BigInt A, BigInt B, BigInt pwd, BigInt K){
	SHA_256 h;
	h.update(params);
	h.update(BigInt::encode(A));
	h.update(BigInt::encode(B));
	h.update(BigInt::encode(pwd));
	h.update(BigInt::encode(K));
	return OctetString(h.final());
}

// add an element to the IHME encode input structure P
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

// create the output message of SPAKE (g^x*M^pwd mod p)
BigInt createMessage(DH_PrivateKey privateKey, BigInt pwd, DL_Group G, BigInt M){
	return (privateKey.get_y()*(power_mod(M, pwd, G.get_p()))) % G.get_p();
}

// The admissible encoding function for one group element of G
BigInt aEncode(z_p_star z, DL_Group G, BigInt in){
	AutoSeeded_RNG rng;
	BigInt gpowq = power_mod(z.g, G.get_q(), z.p);
	BigInt r = BigInt::random_integer(rng, 0, z.a);
	BigInt gpowqr = power_mod(gpowq, r, z.p);
	BigInt mpowainv = power_mod(in, inverse_mod(z.a, G.get_q()), z.p);
	return (gpowqr*mpowainv) % z.p;
}

// admissible decoding for a group element of G
BigInt aDecode(z_p_star z, DL_Group G, BigInt in){
	return power_mod(in, z.a, G.get_p());
}

// initializes an IHME result set S (output of IHME encode function)
gcry_mpi_t* createIHMEResultSet(int numPwds){
	gcry_mpi_t *S;
	S = (gcry_mpi_t*)calloc(numPwds, sizeof(gcry_mpi_t));
	for(int k = 0; k < numPwds; k++)
		S[k] = gcry_mpi_new(0);
	return S;
}

// simulating a keyed PRF as AES encryption of the input
SecureVector<byte> PRF(OctetString k, SecureVector<byte> sid, std::string indicator, InitializationVector *iv){
	AutoSeeded_RNG rng;
	SymmetricKey key = k; // use the BigInt as 256-bit key
	if (iv->length() == 0)
		*iv = InitializationVector(rng, 16); // a random 128-bit IV

	Pipe pipe(get_cipher("AES-256/CBC", key, *iv, ENCRYPTION));

	std::string toEnc = OctetString(sid).as_string()+indicator;
	pipe.process_msg(toEnc);

	SecureVector<byte> out = pipe.read_all(0);

	return out;
}

// utility function to print a byte vector
void print_vector(std::vector<byte> *vec){
	for(int i = 0; i < vec->size();i++){
		printf("%02X", vec->at(i));
	}
}

// utility function: create a buffer for S conversion
std::vector<byte> getSbuf(gcry_mpi_t *S, int numPwds){
	unsigned char *buffer; size_t l; std::vector<byte> Sbuf;
	for (int i = 0; i < numPwds; ++i) {
		gcry_mpi_aprint (GCRYMPI_FMT_USG, &buffer, &l, S[i]);
		Sbuf.insert(Sbuf.end(), buffer, buffer+l);
	}
	return Sbuf;
}

// generate the final key of OSpake
void keyGen(OctetString B, std::vector<byte> Sbuf, OctetString K, OctetString *finalK, InitializationVector *iv){
	std::string forKey = "1";
	// get S as byte vector
	Sbuf.insert(Sbuf.end(), B.begin(), B.begin()+B.length());
	SecureVector<byte> sid(&(Sbuf[0]), Sbuf.size());
	*finalK = OctetString(PRF(K, sid, forKey, iv));
}

// generate server confirmation message of OSpake
void confGen(OctetString B, std::vector<byte> Sbuf, OctetString K, SecureVector<byte> *conf, InitializationVector *iv){
	std::string forConf = "0";
	// get S as byte vector
	Sbuf.insert(Sbuf.end(), B.begin(), B.begin()+B.length());
	SecureVector<byte> sid(&(Sbuf[0]), Sbuf.size());
	*conf = PRF(K, sid, forConf, iv);
}

// compute the SPAKE key
BigInt computeKey(BigInt publicValue, BigInt pwd, BigInt publicKey, DH_PrivateKey privateKey, DL_Group G){
	BigInt NPW = power_mod(publicValue, pwd, G.get_p());
	return power_mod(publicKey*(inverse_mod(NPW, G.get_p())), privateKey.get_x(), G.get_p());
}

// utility function to generate random passwords
void gen_random(char *s, const int len) {
	static const char alphanum[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

// this is it!
int main(int argc, char* argv[])
{
	try
	{
		if (argc < 3)
			std::cout << "Usage: ./ospake <numRuns> <numPwds>\n";
		else {
			double sumServer = 0, sumClient = 0;
			int count = atoi(argv[1]);
			int numPwds = atoi(argv[2]);
			bool errors = false;
			for (int cnt = 0; cnt < count; ++cnt){
				std::cout << ".." << std::flush;

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

				// generate numPwds random passwords
				std::vector<std::string> passwords;
				const int pwdLength = 9;
				for (int var = 0; var < numPwds; ++var) {
					char pwd[pwdLength];
					gen_random(pwd, pwdLength);
					passwords.insert(passwords.end(), pwd);
				}

				// Alice creates a DH key
				clock_gettime(CLOCK_REALTIME, &start);

				// generate private key for Alice
				DH_PrivateKey private_a(rng, G);

				// generate admissible encoding parameters
				z_p_star z = generate_Z(G);

				// IHME structure stuff
				struct point P[numPwds];
				gcry_mpi_t *S;
				for (int k = 0; k < numPwds; k++)
					initpoint(&P[k]);
				int pos = 0;
				S = createIHMEResultSet(numPwds);
				gcry_mpi_t p;
				BigIntToMpi(&p, G.get_p());

				// Alice sends to Bob her public key and a session parameter
				// include password here
				std::vector<BigInt> passwordVector;
				std::vector<BigInt> publicAvector;
				std::vector<BigInt> encoded_public_A_vector;
				for (int var = 0; var < numPwds; ++var) {
					// convert password to Z_N
					BigInt pwdBigInt = Util::pwdToBigInt(passwords.at(var));
					passwordVector.insert(passwordVector.end(), pwdBigInt);

					// compute Alice' public value for current pwd
					BigInt public_A = createMessage(private_a, pwdBigInt, G, M);
					publicAvector.insert(publicAvector.end(), public_A);

					// encode the client's (Alice) messages (admissible encoding)
					BigInt encoded_public_A = aEncode(z, G, public_A);
					encoded_public_A_vector.insert(encoded_public_A_vector.end(), encoded_public_A);

					// add IHME to the admissible encoded values
					addElement(P, &pos, pwdBigInt, encoded_public_A);
				}

				// compute IHME structure S from P with NUM passwords and modulus p
				interpolation_alg2(S, P, numPwds, p);

				//XXX: Alice outputs S and sends it to Bob /////////////////////

				clock_gettime(CLOCK_REALTIME, &stop);
				accumA = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;


				///////////////// BOB //////////////////////////////////////

				// Bob creates a key with a matching group
				clock_gettime(CLOCK_REALTIME, &start);
				DH_PrivateKey private_b(rng, G);

				// Bob sends his public key to Alice
				// include password here
				// FIXME: choose random password for Server
				BigInt serverPwd = passwordVector.at(1);
				BigInt public_b1BigInt = createMessage(private_b, serverPwd, G, N);

				// decode it again (Bob does)
				// IHME decode
				gcry_mpi_t encoded_public_A_MPI, serverPwdNumMPI;
				BigIntToMpi(&serverPwdNumMPI, serverPwd);
				encoded_public_A_MPI = gcry_mpi_new(0);
				decode(encoded_public_A_MPI,S,serverPwdNumMPI,numPwds,p);
				BigInt aEncodedMessageFromAlice = MpiToBigInt(encoded_public_A_MPI);

				// admissible decode
				BigInt bobs_public_A = aDecode(z, G, aEncodedMessageFromAlice);

				// compute k for bob
				BigInt KB = computeKey(M, serverPwd, bobs_public_A, private_b, G);

				// Bob calculates the his keys:
				OctetString bob_key = hashIt(session_param, bobs_public_A, public_b1BigInt, serverPwd, KB);

				// bob calculates hash value for confirmation
				SecureVector<byte> confVal;
				OctetString bobFinalK;
				std::vector<byte> Sbuf = getSbuf(S, numPwds);
				OctetString public_B(BigInt::encode(public_b1BigInt));
				InitializationVector ivKey, ivConf;
				keyGen(public_B, Sbuf, bob_key, &bobFinalK, &ivKey);
				confGen(public_B, Sbuf, bob_key, &confVal, &ivConf);

				clock_gettime(CLOCK_REALTIME, &stop);
				accum = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
				sumServer += accum;
				///////////////////////////////////////////////////////////////////////////////////////////////////

				// XXX: Second part Alice: compute keys ///////////////////////
				clock_gettime(CLOCK_REALTIME, &start);

				// buffer for sid -> confirmation computation
				std::vector<byte> SbufA = getSbuf(S, numPwds);

				// decodes Bobs message
				public_B = OctetString(BigInt::encode(public_b1BigInt));

				// Alice' final key
				OctetString alice_final_key;

				// Now Alice performs the key agreement operation
				// compute keys for alice
				for (int var = 0; var < numPwds; ++var) {
					// compute Alice' key for every password
					BigInt KA = computeKey(N, passwordVector.at(var), public_b1BigInt, private_a, G);
					OctetString alice_key = hashIt(session_param, publicAvector.at(var), public_b1BigInt, passwordVector.at(var), KA);

					// generate confirmation message for every computed key
					SecureVector<byte> confKA;
					confGen(public_B, SbufA, alice_key, &confKA, &ivConf);

					if (confKA == confVal){
						keyGen(public_B, SbufA, alice_key, &alice_final_key, &ivKey);
						break; // XXX: we can stop when we found the correct key; Problem: Side-Channel Attacks
					}
				}

				clock_gettime(CLOCK_REALTIME, &stop);
				accumA += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
				sumClient += accumA;

				if(alice_final_key == bobFinalK)
				{
//					std::cout << "The two keys matched, everything worked\n";
//					std::cout << "The shared key was: " << alice_key.as_string() << "\n";
				}
				else
				{
					errors = true;
//					std::cout << "The two keys didn't match! Hmmm...\n";
//					std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
//					std::cout << "Bob's key was: " << bobFinalK.as_string() << "\n";
				}
			}
			std::cout << "\n";
			if (!errors){
				printf("Timings Server: %lf sec (Average over %u runs on %u passwords)\n", (double)(sumServer/count), count, numPwds);
				printf("Timings Client: %lf sec (Average over %u runs on %u passwords)\n", (double)(sumClient/count), count, numPwds);
			} else
				std::cout << "AAAHHHH...At least one error occurred during computations!\n";
		}
	}
	catch(std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return 1;
	}
	return 0;
}
