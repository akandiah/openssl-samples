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
        0xb6, 0xfe, 0xbf, 0x47, 0x58, 0x9f, 0x8c, 0xd8, 
        0xf0, 0xf9, 0x95, 0xa7, 0x5f, 0x64, 0xf9, 0xa2
	};

    unsigned char iv[CAST_BLOCK];

    unsigned char const iv_data[CAST_BLOCK] = {
        0x65, 0x9c, 0xd2, 0xf3, 0xb9, 0xeb, 0xb, 0x1d
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
    memcpy(iv, iv_data, CAST_BLOCK);

    /* Set the encrypt key structure using the predefined key */
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);

    /* Carry out the encryption */
    CAST_cfb64_encrypt(data, ciphertext, length, &key, iv, &num, CAST_ENCRYPT);

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
    memcpy(iv, iv_data, CAST_BLOCK);

    /* Reset how far we've gone through the IV */
    num = 0;

    /* Carry out the decryption */
    CAST_cfb64_encrypt(ciphertext, plaintext, length, &key, iv, &num, CAST_DECRYPT);

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