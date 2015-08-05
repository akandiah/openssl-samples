#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/bio.h>



int main(void)
{
    int         i;
    BIO*        bio_out;

    DES_cblock          key;

    DES_cblock          inw;
    DES_cblock          outw;

    DES_key_schedule    schedule;

    unsigned char       iv[DES_KEY_SZ]; 

    /* For the purposes of this example, we have chosen the values below
     * for the IV, key1 and key2. In reality, you should generate your own
     * random bytes for these values. For more information, please see 
     * the RNG examples on how this can be done. 
     */
    unsigned char const iv_data[DES_KEY_SZ] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    unsigned char const key1[DES_KEY_SZ] = { 
        0xe1, 0x9c, 0x83, 0x29, 0x47, 0x32, 0x4a, 0x20
    };

    unsigned char const key2[DES_KEY_SZ] = { 
        0xe1, 0x9c, 0x83, 0x29, 0x47, 0x32, 0x4a, 0x20
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";
    
    /* Round up the length to a multiple of 8 */
    int     length  = (strlen(data) + (DES_KEY_SZ - 1)) & ~(DES_KEY_SZ - 1);

    /* Input pointer to OpenSSL's DESX CBC method must be a multiple of 8. */
    /* Hence, use the length calcualted above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 

    /* The output of OpenSSL's DESX CBC method is always a multiple 8. */
    /* Hence, use the length calcualted above. */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the DES_ncbc_encrypt call.*/
    memcpy(iv, iv_data, DES_KEY_SZ);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* In this example, we shall be generating a random key. Before this can
     * happen, we must seed the PRNG. OpenSSL ensures that the PRNG is transparently 
     * seeded on systems that provide the "/dev/urandom" file. 
     */

    /* Cater for seeding the PRNG in Windows */
#ifdef OPENSSL_SYS_WIN32
    /* Add entropy */
#endif
   
    /* Generate the random key (as expected by DES) */
    DES_random_key(&key);

    /* Check the odd parity of the key and its weakness. In doing so, 
     * convert to the architecture dependent format.  
     */
    DES_set_key_checked(&key, &schedule);

    DES_xcbc_encrypt(data_to_encrypt, ciphertext, length, &schedule, (DES_cblock*)iv, (DES_cblock*)key1, (DES_cblock*)key2, DES_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);
    
    BIO_printf(bio_out, "\n\n");

    /* start the decryption process */
    
    /* First, copy the original IV data back to the IV array - as it was 
     * overwritten during the encryption process 
     */
    memcpy(iv, iv_data, DES_KEY_SZ);

    DES_xcbc_encrypt(ciphertext, plaintext, length, &schedule, (DES_cblock*)iv, (DES_cblock*)key1, (DES_cblock*)key2, DES_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);

    free(data_to_encrypt);
    free(ciphertext);
    free(plaintext);

    return 0;
}
