#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#define  KEY_SIZE 32

int main(void)
{
    int			i;
	AES_KEY		key;
	BIO*		bio_out;

	unsigned char key_data[KEY_SIZE] = {
        0x23, 0x33, 0xa1, 0x19, 0xd2, 0x4b, 0x98, 0x75,
        0x77, 0x29, 0xd2, 0x9d, 0xfe, 0x39, 0x36, 0x80,
        0x91, 0x22, 0x11, 0x25, 0x2a, 0xff, 0x46, 0x13,
        0x52, 0x44, 0x48, 0x69, 0xbf, 0xf1, 0x7b, 0x87	
	};

    unsigned char       iv[AES_BLOCK_SIZE];

    unsigned char const iv_data[AES_BLOCK_SIZE] = {
        0xdc, 0x3c, 0x22, 0x78, 0x46, 0x25, 0x67, 0x44,
        0x66, 0x55, 0x79, 0x37, 0x22, 0x94, 0x57, 0x99
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 16 */
    int     length  = (int)(strlen(data) + (AES_BLOCK_SIZE - 1)) & ~(AES_BLOCK_SIZE - 1);

    /* Input pointer to OpenSSL's AES CBC method must be a multiple of 16.      */
    /* Hence, use the length calculated above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 
    
    /* The output of OpenSSL's AES CBC method is a multiple of 16 */
    /* Hence, use the length calcualted above.                    */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array */
    memcpy(iv, iv_data, AES_BLOCK_SIZE);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* Set the encrypt key structure using the predefined key */
    AES_set_encrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    AES_cbc_encrypt(data_to_encrypt, ciphertext, length, &key, iv, AES_ENCRYPT);

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
     * during the encryption process 
     */
    memcpy(iv, iv_data, AES_BLOCK_SIZE);

    /* Set the decrypt key structure using the predefined key */
    AES_set_decrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the decryption */
    AES_cbc_encrypt(ciphertext, plaintext, length, &key, iv, AES_DECRYPT);

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