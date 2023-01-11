/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */
#define HASH_KEY "DpSxTYR8w$Nq5)PjbF2csYYGzKzOsTLV"


int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	SKE_KEY SK;
	size_t x_len = 32;
	unsigned char *x = malloc(x_len);
	size_t iv_size = 16;
	unsigned char IV[iv_size];
	unsigned char rsa_bytes[rsa_numBytesN(K)];
	unsigned char hmac_bytes[HASHLEN];
	size_t kem_len = rsa_numBytesN(K) + HASHLEN;
	unsigned char kem_bytes[kem_len];

	randBytes(x, x_len);
	ske_keyGen(&SK, x, x_len);

	FILE *out_file = fopen(fnOut, "wb");

	rsa_encrypt(rsa_bytes,x,x_len, K);
	HMAC(EVP_sha256(), HASH_KEY, KLEN_SKE, x, x_len, hmac_bytes, 0);

	memcpy(kem_bytes, rsa_bytes, rsa_numBytesN(K));
	memcpy(kem_bytes+rsa_numBytesN(K), hmac_bytes, HASHLEN);

    // Write the kem_bytes to the file
    fwrite(kem_bytes, 1, kem_len, out_file);

    // Close the file
    fclose(out_file);
	
	randBytes(IV, iv_size);
	ske_encrypt_file(fnOut, fnIn, &SK, IV, kem_len);
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	size_t kem_len = rsa_numBytesN(K) + HASHLEN;
	int in_file = open(fnIn, O_RDONLY);
	size_t x_len = 32;
	unsigned char *x = malloc(x_len);
	SKE_KEY SK;

	struct stat sb;
	fstat(in_file, &sb);
	size_t in_file_size = sb.st_size;

	unsigned char *inBuf = mmap(NULL, in_file_size, PROT_READ, MAP_PRIVATE, in_file, 0);
	rsa_decrypt(x, inBuf, rsa_numBytesN(K), K); // get x with RSA private key

	unsigned char hmac_of_x[HASHLEN];
	HMAC(EVP_sha256(), HASH_KEY, KLEN_SKE, x, x_len, hmac_of_x, 0);

	// checks if the hmac in the inBuf is the same as hmac of x we got with RSA 
	for (int i=0; i < HASHLEN; i++) {
		if (hmac_of_x[i] != (inBuf+rsa_numBytesN(K))[i]) {
			return -1;
		}
	}

	ske_keyGen(&SK, x, x_len); // use kdf to get SK
	ske_decrypt_file(fnOut, fnIn, &SK, kem_len); // use SK to decrypt file
	close(in_file);
	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

	RSA_KEY K;

	switch (mode) {
		case ENC:
			{	
				FILE* pub_key_enc = fopen(fnKey, "r");
				rsa_readPublic(pub_key_enc, &K);
				kem_encrypt(fnOut, fnIn, &K);

				pclose(pub_key_enc);
				break;
			}
		case DEC:
			{	
				FILE* priv_key_decryp = fopen(fnKey, "r");
				rsa_readPrivate(priv_key_decryp, &K);
				kem_decrypt(fnOut, fnIn, &K);

				pclose(priv_key_decryp);
				break;
			}
		case GEN:
			{	
				FILE* private_key_file = fopen(fnOut, "w+");
				strcat(fnOut, ".pub");
				FILE* public_key_file = fopen(fnOut, "w+");

				rsa_keyGen(nBits, &K);
				rsa_writePrivate(private_key_file, &K);			
				rsa_writePublic(public_key_file, &K);

				pclose(private_key_file);
				pclose(public_key_file);	
				break;
			}
		default:
			return 1;
	}

	rsa_shredKey(&K);
	return 0;
}
