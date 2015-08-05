#include <stdio.h>
#include <string.h>
#include <openssl/idea.h>
#include <openssl/bio.h>


int main(void)
{

    int                 i;
    BIO*                bio_out;

    /* The IDEA_KEY_SCHEDULE is an expanded form of the IDEA key.
     * Note: We have two separate IDEA_KEY_SCHEDULE structures for
     * encryption and decryption.
     */
    IDEA_KEY_SCHEDULE   enc_key_schedule;
    IDEA_KEY_SCHEDULE   dec_key_schedule;

    unsigned char       iv[IDEA_BLOCK]; 

    unsigned char const iv_data[IDEA_BLOCK] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    static unsigned char key_data[IDEA_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    char*   data    = "The worthwhile problems are the ones you can"
                      "really solve or help solve, the ones you can"
                      "really contribute something to. No "
                      "problem is too small or too trivial if we "
                      "can really do something about it."
                      "- Richard Feynman";

    /* Round up the length to a multiple of 8 */
    int     length  = (strlen(data) + (IDEA_BLOCK - 1)) & ~(IDEA_BLOCK - 1);

    /* Input pointer to OpenSSL's IDEA CBC method must be a multiple of 8. */
    /* Hence, use the length calcualted above and fill the extra bytes with 0's */
    char*   data_to_encrypt = (char*) calloc(length, sizeof(char)); 

    /* The output of OpenSSL's IDEA CBC method is always a multiple 8. */
    /* Hence, use the length calcualted above. */
    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the IDEA_cbc_encrypt call.*/
    memcpy(iv, iv_data, IDEA_BLOCK);

    /* Copy the data to the padded array created earlier */
    memcpy(data_to_encrypt, data, strlen(data));

    /* Set the key structure using the predefined key */
    idea_set_encrypt_key(key_data, &enc_key_schedule);

    /* Carry out the encryption */
    idea_cbc_encrypt(data_to_encrypt, ciphertext, length, &enc_key_schedule, iv, IDEA_ENCRYPT);


    /* Set up the output handling */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < IDEA_BLOCK; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n");

    /* Start the decryption process */

    /* First, copy the original IV data back to the IV array - as it was 
     * overwritten during the encryption process 
     */
    memcpy(iv, iv_data, IDEA_BLOCK);

    /* Set the decrypt key */
    idea_set_decrypt_key(&enc_key_schedule, &dec_key_schedule);

    /* decrypt the data */
    idea_cbc_encrypt(ciphertext, plaintext, length, &dec_key_schedule, iv, IDEA_DECRYPT);
    
    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);

    free(ciphertext);
    free(plaintext);
   
    return 0;

}
