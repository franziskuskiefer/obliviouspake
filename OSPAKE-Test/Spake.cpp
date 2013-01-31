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

#include <stdio.h>

#define BILLION 1000000000L

#include <iostream>
#include <memory>

OctetString hashIt(std::string params, BigInt A, BigInt B, BigInt pwd, BigInt K){
	SHA_256 h;
	h.update(params);
	h.update(BigInt::encode(A));
	h.update(BigInt::encode(B));
	h.update(BigInt::encode(pwd));
	h.update(BigInt::encode(K));
	return OctetString(h.final());
}

BigInt createMessage(DH_PrivateKey privateKey, BigInt pwd, DL_Group G, BigInt M){
	return (privateKey.get_y()*(power_mod(M, pwd, G.get_p()))) % G.get_p();
}

BigInt computeKey(BigInt publicValue, BigInt pwd, BigInt publicKey, DH_PrivateKey privateKey, DL_Group G){
	BigInt NPW = power_mod(publicValue, pwd, G.get_p());
	return power_mod(publicKey*(inverse_mod(NPW, G.get_p())), privateKey.get_x(), G.get_p());
}

int main(int argc, char* argv[])
{
	try
	{
		if (argc < 2)
			std::cout << "Usage: ./ospake <numRuns>\n";
		else {
			double sumServer = 0, sumClient = 0;
			int count = atoi(argv[1]);
			bool errors = false;
			for (int cnt = 0; cnt < count; ++cnt){
				std::cout << "." << std::flush;

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
				BigInt pwd1Num = Util::pwdToBigInt("Password1");

				BigInt public_a1BigInt = createMessage(private_a, pwd1Num, G, M);
				//XXX: Alice outputs public_a1BigInt and sends it to Bob /////////////////////

				clock_gettime(CLOCK_REALTIME, &stop);
				accumA = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;

				///////////////// BOB //////////////////////////////////////

				// Bob creates a key with a matching group
				clock_gettime(CLOCK_REALTIME, &start);
				DH_PrivateKey private_b(rng, G);

				// Bob sends his public key to Alice
				// include password here
				BigInt public_b1BigInt = createMessage(private_b, pwd1Num, G, N);

				// compute k for bob
				BigInt KB = computeKey(M, pwd1Num, public_a1BigInt, private_b, G);

				// Bob calculates the his keys:
				OctetString bob_key = hashIt(session_param, public_a1BigInt, public_b1BigInt, pwd1Num, KB);

				clock_gettime(CLOCK_REALTIME, &stop);
				accum = (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
				sumServer += accum;
				///////////////////////////////////////////////////////////////////////////////////////////////////

				// XXX: Second part Alice: compute keys ///////////////////////
				clock_gettime(CLOCK_REALTIME, &start);

				// Now Alice performs the key agreement operation
				// compute keys for alice
				BigInt KA1 = computeKey(N, pwd1Num, public_b1BigInt, private_a, G);
				OctetString alice_key = hashIt(session_param, public_a1BigInt, public_b1BigInt, pwd1Num, KA1);

				clock_gettime(CLOCK_REALTIME, &stop);
				accumA += (stop.tv_sec - start.tv_sec) + (double)(stop.tv_nsec - start.tv_nsec)/(double)BILLION;
				sumClient += accumA;

				if(alice_key == bob_key) {
					// nothing to do here....
				}
				else { // store error for further use
					errors = true;
				}
			}
			std::cout << "\n";
			if (!errors){
				printf("Timings Server: %lf sec (Average over %u runs)\n", (double)(sumServer/count), count);
				printf("Timings Client: %lf sec (Average over %u runs)\n", (double)(sumClient/count), count);
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
