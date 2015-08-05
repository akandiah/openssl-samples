#include <stdio.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/bio.h>



int main(void)
{
    int         i;
    BIO*        bio_out;

    DES_cblock          key;
    DES_key_schedule    schedule;

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
    
    int     length  = (int) strlen(data);

    /* We would like to feed back 8-bits at a time - i.e. perform 
     * CFB-8, so initialise the variable below to 8. 
     */
    int     numbits = 8;

    /* Allocate the memory for the resulting ciphertext and plaintext */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the DES_cfb_encrypt call.*/
    memcpy(iv, iv_data, DES_KEY_SZ);

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

    DES_cfb_encrypt(data, ciphertext, numbits, length, &schedule, (DES_cblock*)iv, DES_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);

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

    DES_cfb_encrypt(ciphertext, plaintext, numbits, length, &schedule, (DES_cblock*)iv,  DES_DECRYPT);

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
