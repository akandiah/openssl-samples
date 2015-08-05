#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/bio.h>

#define  KEY_SIZE       32
#define  IV_DATA_SIZE   8

int main(void)
{
    int			i;
	AES_KEY		key;
	BIO*		bio_out;

	unsigned char key_data[KEY_SIZE] = {
        0x5d, 0x04, 0x08, 0x3b, 0x55, 0x4e, 0x7d, 0x6c, 
        0x54, 0x5d, 0x45, 0x11, 0xcd, 0xd5, 0x70, 0xe8 
	};

    unsigned char iv[AES_BLOCK_SIZE];

    unsigned char enc_counter[AES_BLOCK_SIZE];

    unsigned char const iv_data[IV_DATA_SIZE] = {
        0x73, 0xa1, 0x2a, 0x82, 0x62, 0x25, 0xa1, 0x13 
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    int     length  = (int) strlen(data);

    /* Initialize how much of the 128-bit encrypted counter block we have used */
    int     num = 0;

    /* Allocate some space for the ciphertext and plaintext */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Clear the encrypted counter */
    memset(enc_counter, 0, AES_BLOCK_SIZE);

    /* Copy the IV data to the front of the IV array. Note: Only 8 bytes are being copied over to a 16-byte array */
    memcpy(iv, iv_data, IV_DATA_SIZE);

    /* Initialize the counter (which is the next 8 bytes of the 16-byte IV array) to 0 */
    memset(iv + IV_DATA_SIZE, 0, IV_DATA_SIZE);

    /* Set the encrypt key structure using the predefined key */
    AES_set_encrypt_key(key_data, KEY_SIZE * 8, &key);

    /* Carry out the encryption */
    AES_ctr128_encrypt(data, ciphertext, length, &key, iv, enc_counter, &num);

    /* Setup output */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data);

    BIO_printf(bio_out, "Ciphertext: ");

    /* Print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Start the decryption process */

    /* First, we have to reset some of the parameters to the way there were before AES_ctr128_encrypt was called */

    /* Clear the encrypted counter */
    memset(enc_counter, 0, AES_BLOCK_SIZE);

    /* Copy the IV data to the front of the IV array. Note: Only 8 bytes are being copied over to a 16-byte array */
    memcpy(iv, iv_data, IV_DATA_SIZE);

    /* Initialize the counter (which is the next 8 bytes of the 16-byte IV array) to 0 */
    memset(iv + IV_DATA_SIZE, 0, IV_DATA_SIZE);

    /* Reset how much of the 128-bit encrypted counter block we have used */
    num = 0;

    /* Note: we don't need to set the decrypt key (as in other samples)  */ 
    /* because encryption and decryption processes are the same for CTR. */

    /* Carry out the decryption */
    AES_ctr128_encrypt(ciphertext, plaintext, length, &key, iv, enc_counter, &num);

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