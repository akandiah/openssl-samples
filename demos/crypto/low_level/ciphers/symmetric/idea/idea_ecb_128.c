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

    static unsigned char key_data[IDEA_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    unsigned char   ciphertext[IDEA_BLOCK];
    unsigned char   plaintext[IDEA_BLOCK];

    /* Open SSL's IDEA ECB encrypt/decrypt function only handles 8 bytes of data */
    char* data_to_encrypt = "8 Bytes.";

    /* Set the key structure using the predefined key */
    idea_set_encrypt_key(key_data, &enc_key_schedule);

    /* Carry out the encryption */
    idea_ecb_encrypt(data_to_encrypt, ciphertext, &enc_key_schedule);

    /* Set up the output handling */

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < IDEA_BLOCK; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)ciphertext)[i]);

    BIO_printf(bio_out, "\n");

    /* Start the decryption process */

    /* Set the decrypt key */
    idea_set_decrypt_key(&enc_key_schedule, &dec_key_schedule);

    /* decrypt the data */
    idea_ecb_encrypt(ciphertext, plaintext, &dec_key_schedule);
    
    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < IDEA_BLOCK; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)plaintext)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
   
    return 0;

}
