#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#define  KEY_SIZE 16

int main(void)
{
	int			i;
	AES_KEY		key;
	BIO*		bio_out;

	unsigned char key_data[KEY_SIZE] = {
        0x23, 0x33, 0xa1, 0x19, 0xd2, 0x4b, 0x98, 0x75,
        0x77, 0x29, 0xd2, 0x9d, 0xfe, 0x39, 0x36, 0x80		
	};

	char   plaintext[AES_BLOCK_SIZE];
	char   ciphertext[AES_BLOCK_SIZE];

    /* Open SSL's AES ECB encrypt/decrypt function only handles 16 bytes of data */
    char*  data   = "Richard Feynman.";

	int    length = (int) strlen(data);

	AES_set_encrypt_key(key_data, KEY_SIZE * 8, &key);

	/* Carry out the encryption */
	AES_ecb_encrypt(data, ciphertext, &key, AES_ENCRYPT);

	/* Set up the IO */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data);
	BIO_printf(bio_out, "\n\n");

	BIO_printf(bio_out, "Ciphertext: ");

	/* print out the ciphertext */
	for (i = 0; i < length; i++)
		BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

	BIO_printf(bio_out, "\n\n");

	/* start the decryption process */

	/* Set the decrypt key */
	AES_set_decrypt_key(key_data, KEY_SIZE * 8, &key);

	/* Carry out the decryption */
	AES_ecb_encrypt(ciphertext, plaintext, &key, AES_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
	/* print out the recovered plaintext */
	for (i = 0; i < length; i++)
		BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

	BIO_printf(bio_out, "\n");

	return 0;

}