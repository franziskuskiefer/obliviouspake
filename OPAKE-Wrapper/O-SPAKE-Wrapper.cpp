/*
 * O-SPAKE-Wrapper.cpp
 *
 *  Created on: Jan 24, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"
#include "O-SPAKE.hpp"

extern "C" {

C_OSpake* initialize(const char* group, int role, const char** pwds, int c, int* pwdLength, const char* crs){
	// init Botan
	Botan::LibraryInitializer init;

	// testing variables
	std::string pwd = "SecurePassword";
	std::vector<std::string> passwords;
	for(int i = 0; i<c; ++i) {
		passwords.push_back(pwds[i]);
	}

	Botan::DL_Group G;
	if (strncmp(group, "1024", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/1024");
	} else if (strncmp(group, "2048", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/2048");
	} else if (strncmp(group, "3072", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/3072");
	} else if (strncmp(group, "4096", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/4096");
	} else if (strncmp(group, "6144", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/6144");
	} else if (strncmp(group, "8192", 4) == 0) {
		G = Botan::DL_Group("modp/ietf/8192");
	}

	// global setup --- variables (M,N)
	Botan::AutoSeeded_RNG rng;
	Botan::BigInt tmp = Botan::BigInt(rng, G.get_p().size());
	Botan::BigInt M = Botan::power_mod(G.get_g(), tmp, G.get_p());

	tmp = Botan::BigInt(rng, (size_t)1024);
	Botan::BigInt N = Botan::power_mod(G.get_g(), tmp, G.get_p());

	const std::string session_param(crs);

	OSpake *result = new OSpake(G, M, N, session_param);
	return (C_OSpake*)result;
}

}
