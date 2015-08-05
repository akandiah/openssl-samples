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
    DES_key_schedule    schedule1;
    DES_key_schedule    schedule2;

    unsigned char const iv_data[DES_KEY_SZ] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    unsigned char       iv[DES_KEY_SZ]; 

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";
    
    int     length  = strlen(data);

    /* Intialise to '0' to indicate that '0' bytes of the IV has been used */
    int     num     = 0;

    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the DES_cfb64_encrypt call.*/
    memcpy(iv, iv_data, DES_KEY_SZ);

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

    /* Check the odd parity of the key and its weakness. In doing so, 
     * convert to the architecture dependent format.  
     */
    DES_set_key_checked(&key1, &schedule1);
    DES_set_key_checked(&key2, &schedule2);

    DES_ede2_cfb64_encrypt(data, ciphertext, length, &schedule1, &schedule2, (DES_cblock*)iv, &num, DES_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);
    
    BIO_printf(bio_out, "\n\n");

    /* start the decryption process */
    
    /* Re-intialise to '0' to indicate that '0' bytes of the IV has been used */
    num = 0;

    /* First, copy the original IV data back to the IV array - as it was 
     * overwritten during the encryption process 
     */
    memcpy(iv, iv_data, DES_KEY_SZ);

    DES_ede2_cfb64_encrypt(ciphertext, plaintext, length, &schedule1, &schedule2, (DES_cblock*)iv, &num, DES_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
 
    free(ciphertext);
    free(plaintext);

    return 0;

}
