#include <stdio.h>
#include <string.h>
#include <openssl/rc4.h>
#include <openssl/bio.h>



int main(void)
{

    int     i;
    BIO*    bio_out;
    RC4_KEY key;

    static unsigned char key_data[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    char*   data_to_encrypt  = "Luck is where preparation meets opportunity."; 
    
    int     length = (int) strlen(data_to_encrypt);

    /* Allocate some memory for the ciphertext */
    unsigned char*  ciphertext = (unsigned char*) malloc(sizeof(char) * length); 

    /* Allocate some memory for the decrypted ciphertext (plaintext) */
    unsigned char*  plaintext  = (unsigned char*) malloc(sizeof(char) * length);


    RC4_set_key(&key, 8, key_data);
    RC4(&key, length, data_to_encrypt, ciphertext);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* The decryption process */

    /* First, we reset the key stream */
    RC4_set_key(&key, 8, key_data);

    /* Carry out the decryption */
    RC4(&key, length, ciphertext, plaintext);

    /* Print out the recovered plaintext */
    BIO_printf(bio_out, "Recovered plaintext: ");

    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n\n");

    BIO_free(bio_out);

    free(ciphertext);
    free(plaintext);

    return 0;
}
