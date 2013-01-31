/*
 * OSpakeTest.c
 *
 *  Created on: Jan 24, 2013
 *      Author: franziskus
 */

#include "O-SPAKE.h"

int main(int argc, char **argv) {
//	const char* group, int role, const char** pwds, int c, int* pwdLength, const char* crs)

	int pwdLength = -1;

	// server
	const char *pwd[] = {"SecurePassword"};
	C_OSpake *server = initialize( "2048", 0, pwd, 3, &pwdLength, "UnserGemeinsamerString");

	// client
	const char *pwds[] = {"123456", "SecurePassword", "GooglePassword"};
	C_OSpake *client = initialize("2048", 0, pwds, 3, &pwdLength, "UnserGemeinsamerString");
}
