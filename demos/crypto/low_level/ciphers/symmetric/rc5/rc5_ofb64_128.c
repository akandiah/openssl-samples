#include <stdio.h>
#include <string.h>
#include <openssl/rc5.h>
#include <openssl/bio.h>

/* OpenSSL's implementation uses 64-bit block sizes and limits rounds to 8, 12 or 16 */


int main(void)
{
    int         i;
    RC5_32_KEY  key;
    BIO*        bio_out;

    /*
     * Using the default key length of 16 (represented by RC5_32_KEY_LENGTH).
     * The maximum length is 255 
     */
    static unsigned char key_data[RC5_32_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    unsigned char       iv[RC5_32_BLOCK];
    
    unsigned char const iv_data[RC5_32_BLOCK] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };


    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 8 */
    int     length  = strlen(data);

    /* Initialize how far we've gone through the IV */
    int     num = 0;

    /* Input pointer to OpenSSL's CBC method must be a multiple of 8. */
    /* Hence, use the length calcualted above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 

    /* The output of OpenSSL's CBC method is always a multiple 8. */
    /* Hence, use the length calcualted above. */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. */
    memcpy(iv, iv_data, RC5_32_BLOCK);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* Set the key structure using the predefined key */
    RC5_32_set_key(&key, RC5_32_KEY_LENGTH, key_data, RC5_12_ROUNDS);

    /* Encrypt the data */
    RC5_32_ofb64_encrypt(data_to_encrypt, ciphertext, length, &key, iv, &num);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Start the decryption process */

    /* First, copy the original IV data back to the IV array - as it was overwritten 
     * during the encryption process 
     */
    memcpy(iv, iv_data, RC5_32_BLOCK);

    /* Reset how far we've gone through the IV */
    num = 0;

    RC5_32_ofb64_encrypt(ciphertext, plaintext, length, &key, iv, &num);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n\n");

    BIO_free(bio_out);

    free(ciphertext);
    free(plaintext);
    free(data_to_encrypt);
   
    return 0;

}
