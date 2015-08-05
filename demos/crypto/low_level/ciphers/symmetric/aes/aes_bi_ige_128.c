#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#define  KEY_SIZE 16

/* 
   For more information about the implementation of Bi-directional IGE in OpenSSL, 
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

    unsigned char       iv[AES_BLOCK_SIZE * 4];

    /* Note: For Bi-directional IGE, the IV is four blocks long */
    unsigned char const iv_data[AES_BLOCK_SIZE * 4] = {
        0x71, 0xfa, 0xce, 0x4c, 0x08, 0x4e, 0xb9, 0xd2, 
        0x16, 0x61, 0x38, 0x26, 0xbf, 0x1e, 0x18, 0x9f, 
        0x87, 0x49, 0xf5, 0x8a, 0x4e, 0xdd, 0x3f, 0x41, 
        0x9c, 0x0f, 0x47, 0x49, 0x46, 0xf8, 0x6d, 0x25,
        0x17, 0x72, 0xb8, 0x83, 0x56, 0x9b, 0x85, 0xbc, 
        0x6a, 0x53, 0x95, 0x5f, 0xd3, 0x41, 0x1b, 0x4a, 
        0x01, 0xcd, 0x51, 0x11, 0xb4, 0x39, 0x63, 0x4d, 
        0xbb, 0x07, 0x77, 0x22, 0x84, 0x31, 0x89, 0x90
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 16 */
    int     length  = (int)(strlen(data) + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1);

    /* Input pointer to OpenSSL's AES Bi-directional IGE method must be a multiple of 16. */
    /* Hence, use the length calculated above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 
    
    /* The output of OpenSSL's AES IGE method is a multiple of 16 */
    /* Hence, use the length calcualted above.                    */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. Note: We are copying four blocks worth of IV data.  */
    memcpy(iv, iv_data, AES_BLOCK_SIZE * 4);

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
     * during the encryption process. Note: We are copying four blocks worth of IV data. 
     */
    memcpy(iv, iv_data, AES_BLOCK_SIZE * 4);

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