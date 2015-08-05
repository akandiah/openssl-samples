#include <stdio.h>
#include <string.h>
#include <openssl/camellia.h>
#include <openssl/bio.h>

#define  KEY_SIZE 16

int main(void)
{
    int			    i;
	CAMELLIA_KEY	key;
	BIO*		    bio_out;

	unsigned char key_data[KEY_SIZE] = {
        0x6d, 0x01, 0x81, 0x09, 0xbb, 0x73, 0xf4, 0xed, 
        0xd2, 0xbf, 0x74, 0x10, 0x45, 0x95, 0xe6, 0x16
	};

    unsigned char iv[CAMELLIA_BLOCK_SIZE];

    unsigned char const iv_data[CAMELLIA_BLOCK_SIZE] = {
        0x73, 0xa1, 0x2a, 0x82, 0x62, 0x25, 0xa1, 0x13, 
        0x75, 0x8e, 0x1e, 0x9e, 0x3b, 0x90, 0xa3, 0x16,
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
    memcpy(iv, iv_data, CAMELLIA_BLOCK_SIZE);

    /* Set the key structure using the predefined key */
    Camellia_set_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    Camellia_ofb128_encrypt(data, ciphertext, length, &key, iv, &num);

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
    memcpy(iv, iv_data, CAMELLIA_BLOCK_SIZE);

    /* Reset how far we've gone through the IV */
    num = 0;

    /* Carry out the decryption */
    Camellia_ofb128_encrypt(ciphertext, plaintext, length, &key, iv, &num);

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