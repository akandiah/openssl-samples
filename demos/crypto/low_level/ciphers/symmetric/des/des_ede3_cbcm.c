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

    /* The IV data to be used by the OFB portion of the encryption */
    unsigned char const iv_data1[DES_KEY_SZ] = {
        0x30, 0xf3, 0x1a, 0x76, 0x91, 0x92, 0x19, 0x4b
    };

    /* The IV data to be used by the CBC portion of the encryption */
    unsigned char const iv_data2[DES_KEY_SZ] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    unsigned char       iv1[DES_KEY_SZ]; 
    unsigned char       iv2[DES_KEY_SZ]; 

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";
    
    /* Round up the length to a multiple of 8 */
    int     length  = (strlen(data) + (DES_KEY_SZ - 1)) & ~(DES_KEY_SZ - 1);

    /* Input pointer to OpenSSL's DES-EDE CBCM method must be a multiple of 8. */
    /* Hence, use the length calcualted above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 

    /* The output of OpenSSL's DES-EDE CBCM method is always a multiple 8. */
    /* Hence, use the length calcualted above. */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV1 data to the IV1 array. */
    memcpy(iv1, iv_data1, DES_KEY_SZ);
    
    /* Copy the IV2 data to the IV2 array. */
    memcpy(iv2, iv_data2, DES_KEY_SZ);

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
   
    /* Generate the random keys (as expected by DES) */
    DES_random_key(&key1);
    DES_random_key(&key2);
    DES_random_key(&key3);

    /* Check the odd parity of the key and their weakness. In doing so, 
     * convert to the architecture dependent format.  
     */
    DES_set_key_checked(&key1, &schedule1);
    DES_set_key_checked(&key2, &schedule2);
    DES_set_key_checked(&key3, &schedule3);

    DES_ede3_cbcm_encrypt(data_to_encrypt, ciphertext, length, &schedule1, &schedule2, &schedule3, (DES_cblock*)iv1, (DES_cblock*)iv2, DES_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);
    
    BIO_printf(bio_out, "\n\n");

    /* start the decryption process */
    
    /* First, copy the original IV data back to the IV arrays - as they have been  
     * overwritten during the encryption process. 
     */
    memcpy(iv1, iv_data1, DES_KEY_SZ);
    memcpy(iv2, iv_data2, DES_KEY_SZ);

    DES_ede3_cbcm_encrypt(ciphertext, plaintext, length, &schedule1, &schedule2, &schedule3, (DES_cblock*)iv1, (DES_cblock*)iv2, DES_DECRYPT);

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
