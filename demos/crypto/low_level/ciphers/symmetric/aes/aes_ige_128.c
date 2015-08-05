#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#define  KEY_SIZE 16

/* 
   For more information about the implementation of IGE in OpenSSL, 
   see: http://www.links.org/files/openssl-ige.pdf
*/

int main(void)
{
    int			i;
	AES_KEY		key;
	BIO*		bio_out;

	unsigned char key_data[KEY_SIZE] = {
        0x23, 0x33, 0xa1, 0x19, 0xd2, 0x4b, 0x98, 0x75,
        0x77, 0x29, 0xd2, 0x9d, 0xfe, 0x39, 0x36, 0x80		
	};

    unsigned char       iv[AES_BLOCK_SIZE * 2];

    /* Note: For IGE, the IV is two blocks long */
    unsigned char const iv_data[AES_BLOCK_SIZE * 2] = {
        0x5c, 0xa6, 0x02, 0x36, 0x64, 0x55, 0xb4, 0x12, 
        0x35, 0xf0, 0x71, 0x23, 0x09, 0x68, 0x74, 0x7a, 
        0xf3, 0x6e, 0xd3, 0x13, 0x5a, 0xcd, 0x66, 0x7e, 
        0x33, 0xbb, 0x06, 0x68, 0xe7, 0xa1, 0x0e, 0x93
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 16 */
    int     length  = (int)(strlen(data) + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1);

    /* Input pointer to OpenSSL's AES IGE method must be a multiple of 16.      */
    /* Hence, use the length calculated above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 
    
    /* The output of OpenSSL's AES CBC method is a multiple of 16 */
    /* Hence, use the length calcualted above.                    */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. Note: We are copying two blocks worth of IV data.  */
    memcpy(iv, iv_data, AES_BLOCK_SIZE * 2);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* Set the encrypt key structure using the predefined key */
    AES_set_encrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    AES_ige_encrypt(data_to_encrypt, ciphertext, length, &key, iv, AES_ENCRYPT);

    /* Setup output */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* Print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Start the decryption process */

    /* First, copy the original IV data back to the IV array - as it was overwritten 
     * during the encryption process. Note: We are copying two blocks worth of IV data. 
     */
    memcpy(iv, iv_data, AES_BLOCK_SIZE * 2);

    /* Set the decrypt key structure using the predefined key */
    AES_set_decrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the decryption */
    AES_ige_encrypt(ciphertext, plaintext, length, &key, iv, AES_DECRYPT);

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