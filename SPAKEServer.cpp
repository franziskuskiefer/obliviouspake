/*
 * SPAKEServer.cpp
 *
 *  Created on: Nov 19, 2012
 *      Author: franziskus
 */

#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>

#include <iostream>
#include <memory>
#include <string>

// boost / network stuff
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using namespace Botan;

struct z_p_start {
	BigInt p;
	BigInt a;
	BigInt g;
	// what else?
};

SecureVector<byte> setSize(BigInt x){
	SecureVector<byte> tmpVec, result;
	tmpVec = BigInt::encode(x);
	result.push_back(tmpVec.size());
	int gSize = result.size();
	result.resize(gSize+tmpVec.size());
	result.copy(gSize, tmpVec, tmpVec.size());
	return result;
}

z_p_start generate_Z(DL_Group G){
//	std::cout << "start generate_Z" << "\n";

	// generate p' = a*p+1
	BigInt q = G.get_q(); // 2047 bit
	bool found = false;
	BigInt a = 2; // stays 2
	AutoSeeded_RNG rng;
	BigInt pp;
	z_p_start result;
	while(!found){
		if (gcd(a, q) == 1){ // will be true first time
			std::cout << "a: " << a << "\n";
			pp = a*q+1;
			if (check_prime(pp, rng)){ // will be true first time
				found = true;
				result.p = pp;
				result.a = a;
				// get a generator for G=Z_p^*
				BigInt gg = BigInt::random_integer(rng, 0, pp); //BigInt(rng, pp.bits()-1);
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

void sendParams(){
//	boost::asio::io_service io_service;
//	tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 6666));
//
//	tcp::socket socket(io_service);
//	acceptor.accept(socket); // wait for client connection

	// generate SPAKE public variables (M,N)
	LibraryInitializer init;
	AutoSeeded_RNG rng;
	DL_Group G("modp/ietf/2048");
	BigInt tmp = BigInt::random_integer(rng, 0, G.get_p());
	BigInt M = power_mod(G.get_g(), tmp, G.get_p());
	tmp = BigInt::random_integer(rng, 0, G.get_p());
	BigInt N = power_mod(G.get_g(), tmp, G.get_p());

	// generate admissible encoding parameters
	z_p_start z = generate_Z(G);

	// select a random message here for test purposes
	BigInt m = power_mod(G.get_g(), BigInt(rng, G.get_p().bits()), G.get_p());
	BigInt gpowq = power_mod(z.g, G.get_q(), z.p);
	BigInt r = BigInt::random_integer(rng, 0, z.a);
//	std::cout << "r: " << r << "\n";
	BigInt gpowqr = power_mod(gpowq, r, z.p);
	BigInt mpowainv = power_mod(m, inverse_mod(z.a, G.get_q()), z.p);
	BigInt res = power_mod(gpowqr*mpowainv, 1, z.p);
//	std::cout << "m: " << m << "\n";
//	std::cout << "inverse encoded m: " << res << "\n";

	// decode test
	BigInt decodedM = power_mod(res, z.a, G.get_p());
	std::cout << "blub: " << (G.get_p()-1)/G.get_q() <<"\n";
	std::cout << "g.p = z.p: " << (G.get_p() == z.p) << "\n";
//	std::cout << "decoded m: " << decodedM<< "\n";
	if (decodedM == m)
		std::cout << "yeehaa :)\n";
	else
		std::cout << "fuuuu :(\n";

//	boost::system::error_code ignored_error;
//	SecureVector<byte> g;
//	g = setSize(G.get_g());
//	std::cout << G.get_g() << "---" << g.size() << "\n";
//	boost::asio::write(socket, boost::asio::buffer(g, g.size()), boost::asio::transfer_all(), ignored_error);
//
//	SecureVector<byte> p;
//	p = setSize(G.get_p());
//	std::cout << G.get_p() << "---" << p.size() << "\n";
//	boost::asio::write(socket, boost::asio::buffer(p, p.size()), boost::asio::transfer_all(), ignored_error);
//
//	SecureVector<byte> m;
//	m = setSize(M);
//	std::cout << M << "---" << m.size() << "\n";
//	boost::asio::write(socket, boost::asio::buffer(m, m.size()), boost::asio::transfer_all(), ignored_error);
//
//	SecureVector<byte> n;
//	n = setSize(N);
//	std::cout << N << "---" << n.size() << "\n";
//	boost::asio::write(socket, boost::asio::buffer(n, n.size()), boost::asio::transfer_all(), ignored_error);
}

int sendMessage(std::string message){
	try {
		boost::asio::io_service io_service;

		tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 6666));

		for (;;) {
			tcp::socket socket(io_service);
			acceptor.accept(socket);

			boost::system::error_code ignored_error;
			boost::asio::write(socket, boost::asio::buffer(message), boost::asio::transfer_all(), ignored_error);
		}
		return 0;
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return 1;
	}
	return 0;
}

int main(int argc, char* argv[]) {
	sendParams();
}
