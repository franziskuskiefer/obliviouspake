/*
 ============================================================================
 Name        : IHME.c
 Author      : David Meier
 Version     :
 Copyright   :
 Description :
 ============================================================================
 */
#include "IHME.h"

#define DEBUG 0


/*
 * Code by Bertram Poettering
 */
void myprint(const gcry_mpi_t x) {
  //gcry_error_t err;
  unsigned char buf[1000];
  size_t nbytes = 0;
  int i;
  //err =
  gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof(buf), &nbytes, x);
  //myerror(err);
  for (i = 0; i < nbytes - 1; i++)
    printf("%c", buf[i]);
}

void assert_fieldelement(const gcry_mpi_t x, const gcry_mpi_t p) {
  assert(gcry_mpi_cmp_ui(x, 0) >= 0 && gcry_mpi_cmp(x, p) < 0);
}

void fieldadd(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p) {
#if 0
  assert_fieldelement(a, p);
  assert_fieldelement(b, p);
  gcry_mpi_add(c, a, b);
  if (gcry_mpi_cmp(c, p) >= 0)
    gcry_mpi_sub(c, c, p);
  assert_fieldelement(c, p);
#else
  gcry_mpi_addm(c, a, b, p);
#endif
}

void fieldsub(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p) {
#if 0
  assert_fieldelement(a, p);
  assert_fieldelement(b, p);
  gcry_mpi_sub(c, a, b);
  if (gcry_mpi_cmp_ui(c, 0) < 0)
    gcry_mpi_add(c, c, p);
  assert_fieldelement(c, p);
#else
  gcry_mpi_subm(c, a, b, p);
#endif
}

void fieldmul(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p) {
#if 0
  assert_fieldelement(a, p);
  assert_fieldelement(b, p);
  gcry_mpi_mul(c, a, b);
  gcry_mpi_mod(c, c, p);
  assert_fieldelement(c, p);
#else
  gcry_mpi_mulm(c, a, b, p);
#endif
}

int my_gcry_mpi_invm(gcry_mpi_t X, gcry_mpi_t A, gcry_mpi_t M) {        // BUGFIX
  gcry_mpi_t h;
  int invertable;
  h = gcry_mpi_new(0);

  invertable = gcry_mpi_gcd(h, A, M);
  if (invertable)
    gcry_mpi_invm(X, A, M);

  gcry_mpi_release(h);
  return invertable;
}
#define GCRY_MPI_INVM my_gcry_mpi_invm

void fielddiv(gcry_mpi_t c, const gcry_mpi_t a, const gcry_mpi_t b, const gcry_mpi_t p) {
  gcry_mpi_t h;
  h = gcry_mpi_new(0);

  assert_fieldelement(a, p);
  assert_fieldelement(b, p);
  assert(GCRY_MPI_INVM(h, b, p));
  gcry_mpi_mul(h, h, a);
  gcry_mpi_mod(c, h, p);
  assert_fieldelement(c, p);

  gcry_mpi_release(h);
}

void initpoint(struct point *p) {
  p->x = gcry_mpi_new(0);
  p->y = gcry_mpi_new(0);
}

void evaluate(gcry_mpi_t val, const gcry_mpi_t *coefs, int len,          /// DRINGEND TESTEN
	      const gcry_mpi_t x, const gcry_mpi_t p) {
  int k;

  gcry_mpi_set(val, coefs[len - 1]);
  for(k = len - 2; k >= 0; k--) {
    fieldmul(val, val, x, p);
    fieldadd(val, val, coefs[k], p);
  }
}

/*
 * end_code
 */


void interpolation_alg1(gcry_mpi_t *c, const struct point *points, const int n, const gcry_mpi_t p) {
	int i, j, k;
	gcry_mpi_t temp;
	temp = gcry_mpi_new(0);


	for (i=0; i < n; i++) {
		gcry_mpi_set(c[i], points[i].y);
	}

	for (k=0; k < (n - 1); k++) {
		for (j = (n - 1); j >= k + 1; j--) {
			fieldsub(c[j], c[j], c[j-1], p);
			fieldsub(temp, points[j].x, points[j-k-1].x, p);
			fielddiv(c[j], c[j], temp, p);
		}
	}

	for (k=n-2; k >= 0; k--) {
		for (j=k; j <= (n-2); j++) {
			fieldmul(temp, points[k].x, c[j+1], p);
			fieldsub(c[j], c[j], temp, p);
		}
	}

	#if DEBUG
		  for(k = 0; k < n; k++) {
			evaluate(temp, c, n, points[k].x, p);
			assert(gcry_mpi_cmp(temp, points[k].y) == 0);
		  }
	#endif

	// Clean up
	gcry_mpi_release(temp);
}

void interpolation_alg2(gcry_mpi_t *c, const struct point *points, const int n, const gcry_mpi_t p) {
	int i, j, k;
	gcry_mpi_t *d;
	gcry_mpi_t temp_1, temp_2;
	temp_1 = gcry_mpi_new(0);
	temp_2 = gcry_mpi_new(0);
	d = (gcry_mpi_t *)calloc(n, sizeof(gcry_mpi_t));
	for (i=0; i < n; i++) {
			d[i] = gcry_mpi_new(0);
			gcry_mpi_set(c[i], points[i].y);
		}

	for (j=n-1; j > 0; j--) {
		fieldsub(c[j], c[j], c[j-1], p);
		fieldsub(d[j-1], points[j].x, points[j-1].x, p);
	}

	for (k=1; k <=(n-2); k++) {
		for (j=(n-1); j >=(k+1); j--) {
			// Implementation of: c[j] = c[j]d[j-1] - c[j-1]d[j]
			fieldmul(temp_1, c[j], d[j-2], p);
			fieldmul(temp_2, c[j-1], d[j-1], p);
			fieldsub(c[j], temp_1, temp_2, p);
			// Implementation of: d[j] = d[j]d[j-1](x[j+1]-x[j-k])
			fieldmul(temp_1, d[j-1], d[j-2], p);
			fieldsub(temp_2, points[j].x, points[j-k-1].x, p);
			fieldmul(d[j-1], temp_1, temp_2, p);
		}
	}

	// Algorithm ??
	for (j=1; j <= (n-1); j++) {
		my_gcry_mpi_invm(d[j-1], d[j-1], p);
		fieldmul(c[j], c[j], d[j-1], p);
	}

	for (k=(n-2); k >= 0; k--) {
		for (j=k; j <= (n-2); j++) {
			fieldmul(temp_1, points[k].x, c[j+1], p);
			fieldsub(c[j], c[j], temp_1, p);
		}
	}

	#if DEBUG
	  for(k = 0; k < n; k++) {
		evaluate(temp_1, c, n, points[k].x, p);
		assert(gcry_mpi_cmp(temp_1, points[k].y) == 0);
	  }
	#endif

	// Clean up
	gcry_mpi_release(temp_1);
	gcry_mpi_release(temp_2);
	free(d);
}

void decode(gcry_mpi_t y, const gcry_mpi_t *c, const gcry_mpi_t x, const int n, const gcry_mpi_t p) {
	int k;
	gcry_mpi_t tmp;
	tmp = gcry_mpi_new(0);
	gcry_mpi_set(y,c[n-1]);
	for (k=n-2;k>=0;k--) {
		fieldmul(tmp,x,y,p);
		fieldadd(y,c[k],tmp,p);
	}
}


// For testing purposes only
// extremely inefficient
void my_pow(gcry_mpi_t w, gcry_mpi_t b, int e) {
	gcry_mpi_set_ui(w, 1);
	while (e >= 0) {
		gcry_mpi_mul(w,b,b);
		e--;
	}
}

void v_fold_interleaving_encode(gcry_mpi_t **c, const struct point *points, const int v, const int numberOfPoints, const gcry_mpi_t p) {
	struct point *d;
	gcry_mpi_t *y;
	int i, j;

	// Initialize Point-Array and y_i
	d = (struct point *)calloc(numberOfPoints, sizeof(struct point));
	y = (gcry_mpi_t *)calloc(numberOfPoints, sizeof(gcry_mpi_t));
	for(j = 0; j < numberOfPoints; j++) {
		 initpoint(&d[j]);
		 d[j].x = gcry_mpi_copy(points[j].x);
		 // Initialize y_i
		 y[j] = gcry_mpi_new(0);
		 y[j] = gcry_mpi_copy(points[j].y);
	}

	for (j=0; j < v; j++) {
		for (i=0; i < numberOfPoints; i++) {
			// Create Point-Array for IHME
			gcry_mpi_div(y[i],d[i].y,y[i],p,0);
		}
		// Run IHME on subset
		interpolation_alg2(c[j],d,numberOfPoints,p);
	}

	// Check assertions
	for (i=0; i < numberOfPoints; i++) {
		assert(gcry_mpi_cmp_ui(y[i], 0) == 0);
	}


	free(d);
	free(y);
}

void v_fold_interleaving_decode(gcry_mpi_t y,  gcry_mpi_t **c, const gcry_mpi_t x, const int v, const int numberOfCoefficients, const gcry_mpi_t p) {
	int k;
	gcry_mpi_t *temp;
	gcry_mpi_t pi_temp;

	pi_temp = gcry_mpi_new(0);

	// Find all needed b by performing std IHME decoding
	temp = (gcry_mpi_t *)calloc(v, sizeof(gcry_mpi_t));
	for (k=0; k < v; k++) {
		temp[k] = gcry_mpi_new(0);
		decode(temp[k],c[k],x,numberOfCoefficients,p);
	}

	// Retranslate results into one result in [0,P^nu]
	// slows down calculation?
	gcry_mpi_set(y,temp[v-1]);
	gcry_mpi_set_ui(pi_temp,1);
	for (k=v-2; k >= 0; k--) {
		gcry_mpi_mul(pi_temp,y,p);
		gcry_mpi_add(y,temp[k],pi_temp);
	}


//	// Check if result is fieldelement of p^nu
//	p_nu = gcry_mpi_new(0);
//	// Calculate p_nu
//	my_pow(p_nu,p,v);
//	assert_fieldelement(y,p_nu);
}
































