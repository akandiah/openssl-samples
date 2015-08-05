#include <stdio.h>
#include <string.h>
#include <openssl/cast.h>
#include <openssl/bio.h>


int main(void)
{
	int			i;
	CAST_KEY	key;
	BIO*		bio_out;

	unsigned char key_data[CAST_KEY_LENGTH] = {
        0x23, 0x33, 0xa1, 0x19, 0xd2, 0x4b, 0x98, 0x75,
        0x77, 0x29, 0xd2, 0x9d, 0xfe, 0x39, 0x36, 0x80		
	};

	char   plaintext[CAST_BLOCK];
	char   ciphertext[CAST_BLOCK];

    /* Open SSL's CAST ECB encrypt/decrypt function only handles 8 bytes of data */
    char*  data   = "8 Bytes.";

	int    length = (int) strlen(data);

	CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);

	/* Carry out the encryption */
	CAST_ecb_encrypt(data, ciphertext, &key, CAST_ENCRYPT);

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

	/* Carry out the decryption */
	CAST_ecb_encrypt(ciphertext, plaintext, &key, CAST_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
	/* print out the recovered plaintext */
	for (i = 0; i < length; i++)
		BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

	BIO_printf(bio_out, "\n");

	return 0;

}