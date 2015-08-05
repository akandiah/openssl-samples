#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/bio.h>



int main(void)
{
    int         i;
    BIO*        bio_out;

    DES_cblock          key1;
    DES_cblock          key2;
    DES_cblock          key3;

    DES_key_schedule    schedule1;
    DES_key_schedule    schedule2;
    DES_key_schedule    schedule3;

    /* Declare the variables to hold the encrypted and decrypted data.
     * Note: DES_cblock is an array of 8 unsigned chars
     */
    DES_cblock          encrypted_data;
    DES_cblock          decrypted_data;

    /* Open SSL's DES ECB encrypt/decrypt function only handle 8 bytes of data */
    char* data_to_encrypt = "8 Bytes.";

    /* In this example, we shall be generating a random key. Before this can
     * happen, we must seed the PRNG. OpenSSL ensures that the PRNG is transparently 
     * seeded on systems that provide the "/dev/urandom" file. 
     */

    /* Cater for seeding the PRNG in Windows */
#ifdef OPENSSL_SYS_WIN32
    /* Add entropy */
#endif
   
    /* Generate two random keys (as expected by DES) */
    DES_random_key(&key1);
    DES_random_key(&key2);
    DES_random_key(&key3);

    /* Check the odd parity of the keys and their weakness. In doing so, 
     * convert to the architecture dependent format.  
     */
    DES_set_key_checked(&key1, &schedule1);
    DES_set_key_checked(&key2, &schedule2);
    DES_set_key_checked(&key3, &schedule3);

    DES_ecb3_encrypt((DES_cblock*)data_to_encrypt, &encrypted_data, &schedule1, &schedule2, &schedule3, DES_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext:%s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < DES_KEY_SZ; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)encrypted_data)[i]);
    
    BIO_printf(bio_out, "\n");

    /* start the decryption process */
    DES_ecb3_encrypt(&encrypted_data, &decrypted_data, &schedule1, &schedule2, &schedule3, DES_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < DES_KEY_SZ; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)decrypted_data)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
 
    return 0;

}
