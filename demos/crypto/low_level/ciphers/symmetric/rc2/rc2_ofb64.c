#include <stdio.h>
#include <string.h>
#include <openssl/rc2.h>
#include <openssl/bio.h>


int main(void)
{
    int     i;
    RC2_KEY key;
    BIO*    bio_out;
    int     num_bytes;

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

    int     length = strlen(data);    
    
    /* Allocate some memory for the ciphertext */
    unsigned char*  ciphertext = (unsigned char*) malloc(sizeof(char) * length); 
    /* Allocate some memory for the decrypted ciphertext (plaintext) */
    unsigned char*  plaintext  = (unsigned char*) malloc(sizeof(char) * length);
    /* Allocate some memory for the bit-stream */
    unsigned char*  bitstream  = (unsigned char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the RC2_cfb64_encrypt call */
    memcpy(iv, iv_data, RC2_BLOCK);

    /* set the key structure using the (unmodified) predefined key */
    RC2_set_key(&key, RC2_KEY_LENGTH, RC2Key, 1024);
    RC2_ofb64_encrypt(data, ciphertext, length, &key, iv, &num_bytes);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* The decryption process */

    /* Reset the number of bytes used */
    num_bytes = 0;

    /* Copy the original IV data back to the IV array - as it was overwritten during the encryption process */
    memcpy(iv, iv_data, RC2_BLOCK);
    RC2_set_key(&key, RC2_KEY_LENGTH, RC2Key, 1024);

    RC2_ofb64_encrypt(ciphertext, plaintext, length, &key, iv, &num_bytes);

    BIO_printf(bio_out, "Recovered plaintext: ");

    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n\n");

    BIO_free(bio_out);

    free(ciphertext);
    free(plaintext);

    return 0;


}
