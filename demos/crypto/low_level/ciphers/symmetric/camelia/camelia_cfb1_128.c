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
        0xfe, 0xec, 0x82, 0x17, 0xb5, 0x1, 0x98, 0x6b, 
        0x5e, 0xf1, 0xb8, 0x6, 0x52, 0x74, 0x2e, 0x52
	};

    unsigned char iv[CAMELLIA_BLOCK_SIZE];

    unsigned char const iv_data[CAMELLIA_BLOCK_SIZE] = {
        0x10, 0x8a, 0xc9, 0x30, 0xb7, 0xf2, 0x35, 0x21, 
        0xfb, 0xac, 0x6b, 0xdf, 0x80, 0x95, 0xeb, 0x1e
    };

    char*   data    = "The worthwhile problems are the ones you can "
                      "really solve or help solve, the ones you can "
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

    /* Set the encrypt key structure using the predefined key */
    Camellia_set_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    /* Note: For CFB-1, the length of the data needs to be specified in bits. */
    /*       Hence, the length is multiplied by 8 before being passed to the call */
    Camellia_cfb1_encrypt(data, ciphertext, length * 8, &key, iv, &num, CAMELLIA_ENCRYPT);

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

    /* Note: we don't need to set the decrypt key (as in other samples)  */ 
    /* because encryption and decryption processes are the same for CFB. */

    /* Carry out the decryption */
    /* Note: For CFB-1, the length of the data needs to be specified in bits */
    /*       Hence, the length is multiplied by 8 before being passed to the call */
    Camellia_cfb1_encrypt(ciphertext, plaintext, length * 8, &key, iv, &num, CAMELLIA_DECRYPT);

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