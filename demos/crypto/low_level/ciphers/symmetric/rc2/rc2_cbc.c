#include <stdio.h>
#include <string.h>
#include <openssl/rc2.h>
#include <openssl/bio.h>


int main(void)
{
    int     i;
    RC2_KEY key;
    BIO*    bio_out;

    unsigned char const iv_data[RC2_BLOCK] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    static unsigned const char RC2Key[RC2_KEY_LENGTH] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    };

    unsigned char   iv[RC2_BLOCK]; 

    char*   data  = "The worthwhile problems are the ones you can"
                    "really solve or help solve, the ones you can"
                    "really contribute something to. No "
                    "problem is too small or too trivial if we "
                    "can really do something about it."
                    "- Richard Feynman";

    /* Round up the length to the higher multiple of 8 */
    int     length = (strlen(data) + (RC2_BLOCK - 1)) & ~(RC2_BLOCK - 1);    


    /* Input pointer to OpenSSL's RC2 CBC method must be a multiple of 8. */
    /* Hence, use the length calcualted above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 

    /* Output pointer to OpenSSL's RC2 CBC method must be a multiple of 8. */
    /* Hence, use the length calcualted above. */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the RC2_cbc_encrypt call */
    memcpy(iv, iv_data, RC2_BLOCK);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* set the key structure using the (unmodified) predefined key */
    RC2_set_key(&key, RC2_KEY_LENGTH, RC2Key, 1024);
    RC2_cbc_encrypt(data_to_encrypt, ciphertext, length, &key, iv, RC2_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Copy the original IV data back to the IV array - as it was overwritten during the encryption process */
    memcpy(iv, iv_data, RC2_BLOCK);

    /* start the decryption process */
    RC2_cbc_encrypt(ciphertext, plaintext, length, &key, iv, RC2_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");

    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n\n");

    BIO_free(bio_out);

    free(data_to_encrypt);
    free(ciphertext);
    free(plaintext);

    return 0;

}
