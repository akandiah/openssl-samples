#include <stdio.h>
#include <string.h>
#include <openssl/blowfish.h>
#include <openssl/bio.h>


#define  BF_KEY_LENGTH 16

int main(void)
{
    int     i;
    BF_KEY  key;
    BIO*    bio_out;

    static unsigned char key_data[BF_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    unsigned char   ciphertext[BF_BLOCK];
    unsigned char   plaintext[BF_BLOCK];

    /* Open SSL's DES ECB encrypt/decrypt function only handles 8 bytes of data */
    char* data_to_encrypt = "8 Bytes.";

    /* set the key structure using the predefined key */
    BF_set_key(&key, BF_KEY_LENGTH, key_data);

    BF_ecb_encrypt(data_to_encrypt, ciphertext, &key, BF_ENCRYPT); 

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < BF_BLOCK; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n");

    /* start the decryption process */
    BF_ecb_encrypt(ciphertext, plaintext, &key, BF_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < BF_BLOCK; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);

	free(ciphertext);
	free(plaintext);
   
    return 0;

}
