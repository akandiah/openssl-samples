#include <stdio.h>
#include <string.h>
#include <openssl/idea.h>
#include <openssl/bio.h>


int main(void)
{

    int                 i;
    BIO*                bio_out;

    /* The IDEA_KEY_SCHEDULE is an expanded form of the IDEA key.
     * Note: Unlike for other modes of encryption in IDEA, we only have one 
     * IDEA_KEY_SCHEDULE structure for encryption and decryption.
     */
    IDEA_KEY_SCHEDULE   key_schedule;

    unsigned char       iv[IDEA_BLOCK]; 

    unsigned char const iv_data[IDEA_BLOCK] = {
        0xcc, 0xfe, 0xcd, 0x3e, 0x21, 0xde, 0x1c, 0x31
    };

    static unsigned char key_data[IDEA_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    char*   data_to_encrypt = "The worthwhile problems are the ones you can"
                              "really solve or help solve, the ones you can"
                              "really contribute something to. No "
                              "problem is too small or too trivial if we "
                              "can really do something about it."
                              "- Richard Feynman";

    int     length  = strlen(data_to_encrypt);

    /* Initialize how far we've gone through the IV */
    int     num = 0;

    char*	ciphertext = (char*) malloc(sizeof(char) * length); 
    char*	plaintext  = (char*) malloc(sizeof(char) * length); 

    /* Copy the IV data to the IV array. The IV array will be updated by the IDEA_cbc_encrypt call.*/
    memcpy(iv, iv_data, IDEA_BLOCK);

    /* Set the key structure using the predefined key */
    idea_set_encrypt_key(key_data, &key_schedule);

    /* Carry out the encryption */
    idea_ofb64_encrypt(data_to_encrypt, ciphertext, length, &key_schedule, iv, &num);

    /* Set up the output handling */
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n\n");

    /* Start the decryption process */

    /* First, copy the original IV data back to the IV array - as it was 
     * overwritten during the encryption process 
     */
    memcpy(iv, iv_data, IDEA_BLOCK);

    /* 
     * Since the same bitstream that was used for encryption needs
     * to be regenerated for decryption, there is no need to generate 
     * a key for decryption 
     */

    /* Reset how far we've gone through the IV */
    num = 0;

    /* decrypt the data */
    idea_ofb64_encrypt(ciphertext, plaintext, length, &key_schedule, iv, &num);
    
    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < length; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
    
    free(plaintext);
    free(ciphertext);
   
    return 0;

}
