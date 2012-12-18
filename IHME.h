/*
 * IHME.h
 *
 *  Created on: 05.10.2010
 *      Author: david
 */

#ifndef IHME_H_
#define IHME_H_

#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <assert.h>
#include <time.h>
/*
 * Code by Bertram Poettering
 */
void myprint(const gcry_mpi_t x);

void assert_fieldelement(const gcry_mpi_t x, const gcry_mpi_t p);

void fieldadd(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p);

void fieldsub(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p);

void fieldmul(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p) ;

int my_gcry_mpi_invm(gcry_mpi_t X, gcry_mpi_t A, gcry_mpi_t M);

#define GCRY_MPI_INVM my_gcry_mpi_invm

void fielddiv(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p);

struct point {
  gcry_mpi_t x;
  gcry_mpi_t y;
};

void initpoint(struct point *p);

void evaluate(gcry_mpi_t val, const gcry_mpi_t *coefs, int len, const gcry_mpi_t x, const gcry_mpi_t p);

/*
 * end_code
 */


void interpolation_alg1(gcry_mpi_t *c, const struct point *points, const int n, const gcry_mpi_t p);

void interpolation_alg2(gcry_mpi_t *c, const struct point *points, const int n, const gcry_mpi_t p);

void decode(gcry_mpi_t y, const gcry_mpi_t *c, const gcry_mpi_t x, const int n, const gcry_mpi_t p);

void v_fold_interleaving_encode(gcry_mpi_t **c, const struct point *points, const int v, const int numberOfPoints, const gcry_mpi_t p);

void v_fold_interleaving_decode(gcry_mpi_t y,  gcry_mpi_t **c, const gcry_mpi_t x, const int v, const int numberOfCoefficients, const gcry_mpi_t p);

int getMuls();
void resetMuls();
#endif /* IHME_H_ */
