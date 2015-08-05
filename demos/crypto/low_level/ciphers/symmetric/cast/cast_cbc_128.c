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

    unsigned char       iv[CAST_BLOCK];

    unsigned char const iv_data[CAST_BLOCK] = {
        0xcc, 0xae, 0xcd, 0x1e, 0xf1, 0x7e, 0x12, 0x51
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 16 */
    int     length  = (int)(strlen(data) + (CAST_BLOCK - 1)) & ~(CAST_BLOCK - 1);

    /* Input pointer to OpenSSL's CAST CBC method must be a multiple of 8.      */
    /* Hence, use the length calculated above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 
    
    /* The output of OpenSSL's CAST CBC method is a multiple of 8 */
    /* Hence, use the length calcualted above.                    */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array */
    memcpy(iv, iv_data, CAST_BLOCK);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* Set the encrypt key structure using the predefined key */
    CAST_set_key(&key, CAST_KEY_LENGTH * 8, key_data);

    /* Carry out the encryption */
    CAST_cbc_encrypt(data_to_encrypt, ciphertext, length, &key, iv, CAST_ENCRYPT);

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
    memcpy(iv, iv_data, CAST_BLOCK);

    /* Carry out the decryption */
    CAST_cbc_encrypt(ciphertext, plaintext, length, &key, iv, CAST_DECRYPT);

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