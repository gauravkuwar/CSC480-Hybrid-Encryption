#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char* buf = malloc(len);
	Z2BYTES(buf,len,x);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */
	 
	rsa_initKey(K);

	// gets randon bytes and turn them into integer and then gets the next prime for p and q
	// didn't know what the expected way was, but this got me to pass
	// the test cases and seems to work
	int rand_size = 2;
	int pq_bytes = (keyBits / 8) / 2; // cause 8 bits in a byte and we numtiple p and q

	unsigned char* rand_bytes_p = malloc(pq_bytes);
	unsigned char* rand_bytes_q = malloc(pq_bytes);
	unsigned char* rand_bytes_num = malloc(rand_size);

	randBytes(rand_bytes_p, pq_bytes);
	BYTES2Z(K->p, rand_bytes_p, pq_bytes);
	mpz_nextprime(K->p, K->p);
	
	randBytes(rand_bytes_q, pq_bytes);
	BYTES2Z(K->q, rand_bytes_q, pq_bytes);
	mpz_nextprime(K->q, K->q);

	// gmp_printf("p %Zd\n", K->p);
	// gmp_printf("q %Zd\n", K->q);

	// n = p * q
	mpz_mul(K->n, K->p, K->q);
	// gmp_printf("n %Zd\n", K->n);

	NEWZ(gcd); 
	NEWZ(phi_n);
	NEWZ(p_1); 
	NEWZ(q_1);
	NEWZ(rand_num);

	// All parts do: phi(n) = (p-1) * (q-1)
	mpz_sub_ui(p_1, K->p, 1);
	mpz_sub_ui(q_1, K->q, 1);
	mpz_mul(phi_n, p_1, q_1);

	// gmp_printf("phi_n %Zd\n", phi_n);

	// get e, but checking numbers from 2 to phi_n
	// and getting the first number that is coprime with phi_n,
	// by checking gcd of e and phi_n
	
	mpz_set_ui(K->e, 1);

	// so here I tried to get an e which is not the first see one in the range [2, phi(n)),
	// making it larger in size. Not really sure if it makes it more secure tho
	randBytes(rand_bytes_num, rand_size);
	BYTES2Z(rand_num, rand_bytes_num, rand_size);
	
	while ((mpz_cmp_ui(rand_num, 1) != 0 || mpz_cmp_ui(gcd, 1) != 0) && mpz_cmp(K->e, phi_n) != 1) {
		mpz_add_ui(K->e, K->e, 1);
		mpz_gcd(gcd, K->e, phi_n);
		randBytes(rand_bytes_num, rand_size);
		BYTES2Z(rand_num, rand_bytes_num, rand_size);
	}

	// to solve for d in de congurent to 1 (mod phi(n))
	mpz_invert(K->d, K->e, phi_n);

	// gmp_printf("e %Zd\n", K->e);
	// gmp_printf("d %Zd\n", K->d);

	// free space
	mpz_clear(phi_n);
	mpz_clear(gcd);
	mpz_clear(p_1);
	mpz_clear(q_1);
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */

	NEWZ(m); NEWZ(ct);
	// turns the inBuf into integer m (message) to be encrypted
	BYTES2Z(m, inBuf, len); 
	// gmp_printf("m %Zd\n", m);

	// ct = (m ^ e) % n
	mpz_powm(ct, m, K->e, K->n);
	// gmp_printf("ct %Zd\n", ct);

	Z2BYTES(outBuf,len, ct); // store encrypted ciphertext in outBuf

	// free space
	mpz_clear(m);
	mpz_clear(ct);
	return len; /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	NEWZ(ct); NEWZ(dt);
	BYTES2Z(ct, inBuf, len); // turns the inBuf into integer ct to be decrypted
	// gmp_printf("ct %Zd\n", ct);

	// dt = (ct ^ d) % n
	mpz_powm(dt, ct, K->d, K->n);
	// gmp_printf("dt %Zd\n", dt);

	Z2BYTES(outBuf, len, dt); // store decrypted text in outBuf

	// free space
	mpz_clear(ct);
	mpz_clear(dt);
	return len;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
