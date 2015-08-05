#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <openssl/dh.h>

/* For gaining entropy information on Windows*/
#ifdef _WIN32
#include <Wincrypt.h>
#endif


#define ENTROPY_SIZE    20


#ifdef  _WIN32
/* This function uses Microsoft's CryptoAPI to generate seed data */
void obtain_seed_data(unsigned char* seed_data, int length)
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

void obtain_seed_data(unsigned char* seed_data, int length)
{



}


#endif





/* This example will demonstrate the Diffie-Hellman-Merkle exchange with two parties */


int main(void)
{

    DH* alice   = NULL;
    DH* bob     = NULL;

    unsigned char   seed_data[ENTROPY_SIZE];

    /* First off, we seed the random number generator */
    obtain_seed_data(seed_data, ENTROPY_SIZE);
    RAND_seed(seed_data, ENTROPY_SIZE);

    
    





    return 0;

}
