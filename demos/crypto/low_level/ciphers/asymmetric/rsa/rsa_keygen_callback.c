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


#define  ENTROPY_SIZE   20
#ifdef  _WIN32

/* This function uses Microsoft's CryptoAPI to generate seed data */
static void obtain_seed_data(unsigned char* seed_data, int length)
{
    
    HCRYPTPROV providerHandle;

    if (!CryptAcquireContext(&providerHandle, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        fprintf(stderr, "A cryptographic service handle could not be acquired\n");
        exit(1);
    }

    if (!CryptGenRandom(providerHandle, length, seed_data))
    {
        fprintf(stderr, "Error during CryptGenRandom\n");
        CryptReleaseContext(providerHandle, 0);
        exit(1);
    }
    
}

#else

static void obtain_seed_data(unsigned char* seed_data, int length)
{



}


#endif



/*
 *  NOTE: This comments below are only applicable for the built-in key generator.
 *        This is the key generator that should be used by default.
 *
 *  This function defines the call-back function which provides feedback 
 *  (to the user) about the key generation. There are 3 instances where this 
 *  function can be called:
 *      
 *      * While a random prime number is being generated using BN_generate_prime()
 *      * When the n-th randomly generated prime number is rejected as not suitable 
 *        for the key.
 *      * When a random p has been found with p-1 being relatively prime to e 
 *
 *
 *  When BN_generate_prime() is being called, the following values for the parameters 
 *  can be expected:
 *
 *      status_code:
 *          0 - A potential prime has been found   
 *          1 - The number under consideration is being tested for primality
 *          2 - A prime has definitely been found
 *
 *      arg:
 *          The argument is dependent on the status codes specified above. The following 
 *          list describes the meaning of the argument for the status codes specified above:
 *
 *          status_code = 0, arg = Number of potential primes found so far 
 *                                (not including the one under consideration). 
 *
 *          status_code = 1, arg = Number of Miller-Rabin probabilistic primality tests 
 *                                 that have been performed.
 *
 *          status_code = 2, arg = Number of possible primes that have been tested before.
 *
 *  When the n-th randomly generated prime number is rejected, the following parameters 
 *  can be expected:
 *      
 *      status_code = 2,    arg = The n-th number that has been found as not being suitable
 *
 *  When a random p has been found with p-1 being relatively prime to e:
 *
 *      status_code = 3,    arg = 0
 *
 */
static void generation_status(int status_code, int arg, void* cb_arg)
{
    

}


/* 
 * In this example, we shall generate one RSA key pair and 
 * print out the contents of their parameters.
 */

int main(void) 
{
    BIO*    bio_out;
    RSA*    key_pair            = NULL;
    BIGNUM* public_key_exponent = NULL;

    unsigned char   seed_data[ENTROPY_SIZE];
    
    /* Setup the output */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* Before generating the keys, the pseudo-random number generator must be seeded */
    obtain_seed_data(seed_data, ENTROPY_SIZE);
    RAND_seed(seed_data, ENTROPY_SIZE);

    BIO_printf(bio_out, "\nGenereating key pair:\n");
    
    /* Generate a 2048-bit key pair with a public exponent of 65537 (RSA_F4) */
    public_key_exponent = BN_new();
    key_pair            = RSA_new();

    BN_set_word(public_key_exponent, RSA_F4);
    RSA_generate_key_ex(key_pair, 2048, public_key_exponent, NULL);

    BIO_printf(bio_out, "-----------------------\n\n");
    
    BIO_printf(bio_out, "Value for the modulus \"n\":\n");
    BN_print(bio_out, key_pair -> n); 
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for the distinct prime, \"p\":\n");
    BN_print(bio_out, key_pair -> p);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for the distinct prime, \"q\":\n");
    BN_print(bio_out, key_pair -> q);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for \"dP\":\n");
    BN_print(bio_out, key_pair -> dmp1);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for \"dQ\":\n");
    BN_print(bio_out, key_pair -> dmq1);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for \"qInv\":\n");
    BN_print(bio_out, key_pair -> iqmp);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for the public key exponent \"e\":\n");
    BN_print(bio_out, key_pair -> e);
    BIO_printf(bio_out, "\n\n");

    BIO_printf(bio_out, "Value for the private key exponent \"d\":\n");
    BN_print(bio_out, key_pair -> d);
    BIO_printf(bio_out, "\n\n");

    return 0;
}