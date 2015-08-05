#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#ifdef APP_DEBUG
/* For gaining entropy information on Windows*/
#ifdef _WIN32
#include <Wincrypt.h>
#endif

#define SEED_SIZE   20


/*
 * Note: The idea, and the keys for this example have been taken from rsa_test.c. 
 *       This file is available in the crypto/rsa/ directory in the
 *       root folder of the OpenSSL distribution.
 */



void set_public_key(RSA* public_key)
{
    static unsigned char e[] = "\x11";

    static unsigned char n[] =
        "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
        "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
        "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
        "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
        "\xF5";

    public_key -> e = BN_bin2bn(e, sizeof(e) - 1, public_key -> e);
    public_key -> n = BN_bin2bn(n, sizeof(n) - 1, public_key -> n);
}


void set_private_key(RSA* private_key)
{
    static unsigned char n[] =
        "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
        "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
        "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
        "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
        "\xF5";

    static unsigned char d[] =
        "\x0A\x03\x37\x48\x62\x64\x87\x69\x5F\x5F\x30\xBC\x38\xB9\x8B\x44"
        "\xC2\xCD\x2D\xFF\x43\x40\x98\xCD\x20\xD8\xA1\x38\xD0\x90\xBF\x64"
        "\x79\x7C\x3F\xA7\xA2\xCD\xCB\x3C\xD1\xE0\xBD\xBA\x26\x54\xB4\xF9"
        "\xDF\x8E\x8A\xE5\x9D\x73\x3D\x9F\x33\xB3\x01\x62\x4A\xFD\x1D\x51";

    static unsigned char p[] =
        "\x00\xD8\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x12"
        "\x0D";

    static unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x89";

    static unsigned char dmp1[] =
        "\x59\x0B\x95\x72\xA2\xC2\xA9\xC4\x06\x05\x9D\xC2\xAB\x2F\x1D\xAF"
        "\xEB\x7E\x8B\x4F\x10\xA7\x54\x9E\x8E\xED\xF5\xB4\xFC\xE0\x9E\x05";

    static unsigned char dmq1[] =
        "\x00\x8E\x3C\x05\x21\xFE\x15\xE0\xEA\x06\xA3\x6F\xF0\xF1\x0C\x99"
        "\x52\xC3\x5B\x7A\x75\x14\xFD\x32\x38\xB8\x0A\xAD\x52\x98\x62\x8D"
        "\x51";

    static unsigned char iqmp[] =
        "\x36\x3F\xF7\x18\x9D\xA8\xE9\x0B\x1D\x34\x1F\x71\xD0\x9B\x76\xA8"
        "\xA9\x43\xE1\x1D\x10\xB2\x4D\x24\x9F\x2D\xEA\xFE\xF8\x0C\x18\x26";    

 
    /* Set the values pertaining to the private key */
    /* Note: The values for p, q, dmp1, dmq1 and iqmp are not necessary.
             However, if these values are provided, decryption can be carried
             out quickly. For more information, see:
             http://en.wikipedia.org/wiki/RSA_(algorithm)#Using_the_Chinese_remainder_algorithm
     */

    private_key -> n = BN_bin2bn(n, sizeof(n) - 1, private_key -> n);
    private_key -> d = BN_bin2bn(d, sizeof(d) - 1, private_key -> d);

    private_key -> p = BN_bin2bn(p, sizeof(p) - 1, private_key -> p);
    private_key -> q = BN_bin2bn(q, sizeof(q) - 1, private_key -> q);
    private_key -> dmp1 = BN_bin2bn(dmp1, sizeof(dmp1) - 1, private_key -> dmp1);
    private_key -> dmq1 = BN_bin2bn(dmq1, sizeof(dmq1) - 1, private_key -> dmq1);
    private_key -> iqmp = BN_bin2bn(iqmp, sizeof(iqmp) - 1, private_key -> iqmp);

}

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



int main(void)
{

    RSA public_key;
    RSA private_key;

    unsigned char entropy_data[SEED_SIZE];

    /* The data to encrypt. The data, in ASCII form is: "Test Data!" */
    unsigned char data[] = "\x54\x65\x73\x74\x20\x44\x61\x74\x61\x21";

    /* Length of the above data */
    int data_length      = sizeof(data) - 1;

    /* Seed the random number generator */
    generate_seed(entropy_data, SEED_SIZE);

    /* Set-up the public key */
    set_public_key(&public_key);

    RSA_public_encrypt(data_length, data, 


    

        
    
    

    set_public_key(public_key);
    set_private_key(private_key);




    return 0;
}

#endif


int main(void) 
{
    unsigned char output[2048];
    RSA* key =  RSA_generate_key(1024, 65537, NULL, NULL);
    BN_bn2bin(key->n, output);
    printf("%s\n", output);

    printf("here\n");
}