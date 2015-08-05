/*
**
** WARNING: RSA should not be used as a general purpose encryption algorithm. That is, it should
**          not be used when encrypting messages where symmetric algorithms can be easily substituted. 
**
**          There are serveral reasons for this:
**
**          1) It is extremely slow (when compared to symmetric algorithms).
**          2) Depending on the padding mechanism chosen, it can only encrypt:
**                  # Up to 'n' bytes when the no padding scheme is used
**                  # Up to n - 11 bytes when PKCS #1 v1.5 padding scheme is used
**                  # Up to n - (2*h + 2) bytes when the EME-OAEP padding scheme is used.
**                    
**                  Where 'n' is the length of the modulus (in bytes) and 'h' is the length 
**                  of the hash function's output (in bytes).
**
**          Hence, RSA encryption should only be used for the purposes of: signing and wrapping keys.
**          
**          What is demonstrated in this example is purely for the purposes of exemplifying the concepts 
**          involved in RSA encryption/decryption. So please, do not use it where a symmetric cipher will suffice.
**
*/



#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>


/* For gaining entropy information on Windows*/
#ifdef _WIN32
#include <Wincrypt.h>
#endif

#define SEED_SIZE   20




/* For Windows environments */
#ifdef _WIN32

void generate_seed(unsigned char* seed, int length)
{
    HCRYPTPROV providerHandle;

    if (!CryptAcquireContext(&providerHandle, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        fprintf(stderr, "A cryptographic service handle could not be acquired\n");
        exit(1);
    }

    if (!CryptGenRandom(providerHandle, length, seed))
    {
        fprintf(stderr, "Error during CryptGenRandom\n");
        CryptReleaseContext(providerHandle, 0);
        exit(1);
    }
    
}

#else

/* For all other *nix environments */
void generate_seed(unsigned char* seed, int length)
{


}

#endif



RSA* retrieve_public_key(RSA* key_pair)
{
    RSA* public_key = RSA_new();
    public_key -> e = BN_dup(key_pair -> e);
    public_key -> n = BN_dup(key_pair -> n);

    return public_key;
}


RSA* retrieve_private_key(RSA* key_pair)
{
    RSA* private_key = RSA_new();
    
    private_key -> n = BN_dup(key_pair -> n);
    private_key -> p = BN_dup(key_pair -> p);
    private_key -> q = BN_dup(key_pair -> q);

    private_key -> dmp1 = BN_dup(key_pair -> dmp1);
    private_key -> dmq1 = BN_dup(key_pair -> dmq1);
    private_key -> iqmp = BN_dup(key_pair -> iqmp);

    private_key -> d = BN_dup(key_pair -> d);
    
    return private_key;
}


int main(void)
{
    int     i;
	BIO*    bio_out;

    RSA*    public_key          = NULL;
    RSA*    private_key         = NULL;
    BIGNUM* public_key_exponent = NULL;
    RSA*    key_pair            = NULL;

    int     ciphertext_len      = 0;
    int     plaintext_len       = 0;
    unsigned char*  ciphertext  = NULL;
    unsigned char*  plaintext   = NULL;


    unsigned char   seed_data[SEED_SIZE];

    /* The data to encrypt. The data, in ASCII form is: "Test Data!" */
    unsigned char data[]  = "\x54\x65\x73\x74\x20\x44\x61\x74\x61\x21";

    /* Length of the above data. For PKCS #1 v1.5, this length must be 11 bytes less than the size of the modulus */
    int data_length       = sizeof(data) - 1;

    /* Before generating the keys, the pseudo-random number generator must be seeded */
    generate_seed(seed_data, SEED_SIZE);
    RAND_seed(seed_data, SEED_SIZE);

    /* Generate a 2048-bit key pair with a public exponent of 65537 (RSA_F4) */
    public_key_exponent = BN_new();
    key_pair            = RSA_new();

    BN_set_word(public_key_exponent, RSA_F4);
    RSA_generate_key_ex(key_pair, 2048, public_key_exponent, NULL);

    /*
        NOTE: In the following instance, we split the key-pair in to public and private keys.
              This is not necessary for this code to be functional. We do this because we don't
              want our private key information to be distributed with the public key.
    */

    public_key  = retrieve_public_key(key_pair);
    private_key = retrieve_private_key(key_pair);

    /* Retrieve the ciphertext length (i.e. size of the modulus) */
    ciphertext_len  = RSA_size(public_key);

    /* Allocate the required amount of memory for the ciphertext. */
    ciphertext      = (unsigned char*) calloc(ciphertext_len, sizeof(unsigned char));    
    
    /* Carry out the encryption */
    if ((ciphertext_len = RSA_public_encrypt(data_length, data, ciphertext, public_key, RSA_PKCS1_OAEP_PADDING)) == -1)
    {        
        fprintf(stderr, "Error carrying out encryption. Error code: %lu\n", ERR_get_error());
        exit(1);
    }

    /* Setup output */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);
    BIO_printf(bio_out, "Ciphertext: ");


    /* Print out the ciphertext */
    for (i = 0; i < ciphertext_len; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");


    /* Start the decryption process */

    /* Allocate the same amount of memory (as for the ciphertext) for the plaintext. */
    plaintext   = (unsigned char*) calloc(ciphertext_len, sizeof(unsigned char)); 

    /* Now, carry out the decryption */ 
    if ((plaintext_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, private_key, RSA_PKCS1_OAEP_PADDING)) == -1)
    {
        fprintf(stderr, "Error carrying out the decryption. Error code: %lu\n", ERR_get_error());
        exit(1);
    }
        
    BIO_printf(bio_out, "Recovered plaintext: ");    

    /* Print out the plaintext. Note: We use the length returned by RSA_private_decrypt */
    for (i = 0; i < plaintext_len; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n\n");


    free(ciphertext);
    free(plaintext);

    BIO_free(bio_out);

    RSA_free(public_key);
    RSA_free(private_key);
    RSA_free(key_pair);

    return 0;
}


