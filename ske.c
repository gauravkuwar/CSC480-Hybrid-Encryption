#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */
#define KDF_HASH_KEY "#JCicvr1IsIyjH&Cph60Au!m@V*yA45x"
// different hash key for the hmac of KDF

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	 // random if entropy is not given
	 if (entropy == 0 && entLen == 0) {
		randBytes(K->hmacKey, KLEN_SKE);
		randBytes(K->aesKey, KLEN_SKE);
	 } else { // get keys from entropy
		HMAC(EVP_sha256(), KDF_KEY, KLEN_SKE, entropy, entLen, K->hmacKey, 0);
		HMAC(EVP_sha256(), KDF_HASH_KEY, KLEN_SKE, entropy, entLen, K->aesKey, 0);
	 }

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV, size_t offset)
{	
	// I added offset here, because it was stuck on a problem with nmap and 
	// offset parameter, so I just added my own offset, so I don't waste time on
	// that. Sorry!

	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	unsigned char hmac[HM_LEN];
	unsigned int hmac_len;
	
	memcpy(outBuf+offset, IV, AES_BLOCK_SIZE);
	/* encrypt: basic encryption with aes ctr */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,IV))
		ERR_print_errors_fp(stderr);

	int nWritten;
	if (1!=EVP_EncryptUpdate(ctx,outBuf+AES_BLOCK_SIZE+offset,&nWritten,inBuf,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);

	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, outBuf+offset, nWritten+AES_BLOCK_SIZE, hmac, &hmac_len);

	memcpy(outBuf + offset + nWritten + AES_BLOCK_SIZE, hmac, hmac_len);
	return nWritten + AES_BLOCK_SIZE + HM_LEN; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	// Open the files
	int in_file = open(fnin, O_RDONLY);
	int out_file = open(fnout, O_RDWR | O_CREAT, 0644);
	struct stat sb;
	
	fstat(in_file, &sb);
	size_t in_file_size = sb.st_size;

	// Map the file into memory
	unsigned char *inBuf = mmap(NULL, in_file_size, PROT_READ, MAP_PRIVATE, in_file, 0);
	size_t ctLen = ske_getOutputLen(in_file_size);
	
	// Set the size of the file
    ftruncate(out_file, ctLen+offset_out);
	unsigned char *outBuf = mmap(NULL, ctLen, PROT_WRITE, MAP_SHARED, out_file, 0);

	// encrypt file
	size_t bytes_written = ske_encrypt(outBuf,inBuf,in_file_size,K,IV,offset_out);
	msync(outBuf, bytes_written, MS_SYNC);

	// clean up
	munmap(inBuf, in_file_size);
	munmap(outBuf, ctLen);
	// Close the files
	close(in_file);
	close(out_file);
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, size_t offset)
{

	// I added offset here, because it was stuck on a problem with nmap and 
	// offset parameter, so I just added my own offset, so I don't waste time on
	// that. Sorry!
	
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned char IV[AES_BLOCK_SIZE];
	unsigned char hmac_of_ciphertext[HM_LEN];
	unsigned int hmac_len;
	size_t ciphertext_len = len - HM_LEN - AES_BLOCK_SIZE - offset;
	
	memcpy(IV, inBuf+offset, AES_BLOCK_SIZE);
	HMAC(EVP_sha256(), K->hmacKey, KLEN_SKE, inBuf+offset, len-HM_LEN-offset, hmac_of_ciphertext, &hmac_len);

	// checks if the hmac in the inBuf is the same as hmac produced with the ciphertext 
	for (int i=0; i < HM_LEN; i++) {
		if (hmac_of_ciphertext[i] != (inBuf+(len-HM_LEN))[i]) {
			return -1;
		}
	}
	// basic decryption with aes ctr
	int nWritten = 0;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey, IV))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,outBuf,&nWritten,inBuf+AES_BLOCK_SIZE+offset,ciphertext_len))
		ERR_print_errors_fp(stderr);
	// fprintf(stderr, "%s\n",outBuf);

	return nWritten;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	// Open the files
	int in_file = open(fnin, O_RDONLY);
	int out_file = open(fnout, O_RDWR | O_CREAT, 0644);;
	struct stat sb;
	
	fstat(in_file, &sb);
	size_t in_file_size = sb.st_size;

	// Map the file into memory
	unsigned char *inBuf = mmap(NULL, in_file_size, PROT_READ, MAP_PRIVATE, in_file, 0);
	size_t ciphertext_size = in_file_size - HM_LEN - AES_BLOCK_SIZE - offset_in;

	// Set the size of the file
    ftruncate(out_file, ciphertext_size);
	
	unsigned char *outBuf = mmap(NULL, ciphertext_size, PROT_WRITE, MAP_SHARED, out_file, 0);
	// encrypt file
	size_t bytes_written = ske_decrypt(outBuf,inBuf,in_file_size,K, offset_in);
	msync(outBuf, bytes_written, MS_SYNC);

	// clean up
	munmap(inBuf, in_file_size);
	munmap(outBuf, ciphertext_size);
	// Close the files
	close(in_file);
	close(out_file);
	return 0;
}
