/*
 * O-SPAKE.h
 *
 *  Created on: Jan 24, 2013
 *      Author: franziskus
 */

#ifndef O_SPAKE_H_
#define O_SPAKE_H_

typedef void C_OSpake;

#ifdef __cplusplus
extern "C" {
#endif

// ROLE: 0 for server, 1 for client
C_OSpake* initialize(const char* group, int role, const char** pwds, int c, int* pwdLength, const char* crs);

#ifdef __cplusplus
}
#endif

#endif /* O_SPAKE_H_ */
