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
        0xb6, 0xfe, 0xbf, 0x47, 0x58, 0x9f, 0x8c, 0xd8, 
        0xf0, 0xf9, 0x95, 0xa7, 0x5f, 0x64, 0xf9, 0xa2
	};

    unsigned char iv[AES_BLOCK_SIZE];

    unsigned char const iv_data[AES_BLOCK_SIZE] = {
        0x65, 0x9c, 0xd2, 0xf3, 0xb9, 0xeb, 0xb, 0x1d, 
        0xe3, 0x8b, 0x19, 0xa, 0xd7, 0x13, 0x4b, 0x41
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    int     length  = (int) strlen(data);

    /* Initialize how far we've gone through the IV */
    int     num = 0;

    /* Allocate some space for the ciphertext and plaintext */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array */
    memcpy(iv, iv_data, AES_BLOCK_SIZE);

    /* Set the encrypt key structure using the predefined key */
    AES_set_encrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    AES_cfb128_encrypt(data, ciphertext, length, &key, iv, &num, AES_ENCRYPT);

    /* Setup output */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);

    BIO_printf(bio_out, "Ciphertext: ");

    /* Print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Start the decryption process */

    /* First, copy the original IV data back to the IV array - as it was overwritten 
     * during the encryption process 
     */
    memcpy(iv, iv_data, AES_BLOCK_SIZE);

    /* Reset how far we've gone through the IV */
    num = 0;

    /* Note: we don't need to set the decrypt key (as in other samples)  */ 
    /* because encryption and decryption processes are the same for CFB. */

    /* Carry out the decryption */
    AES_cfb128_encrypt(ciphertext, plaintext, length, &key, iv, &num, AES_DECRYPT);

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