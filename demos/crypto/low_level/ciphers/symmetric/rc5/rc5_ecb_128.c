#include <stdio.h>
#include <string.h>
#include <openssl/rc5.h>
#include <openssl/bio.h>

/* OpenSSL's implementation uses 64-bit block sizes and limits rounds to 8, 12 or 16 */


int main(void)
{
    int         i;
    RC5_32_KEY  key;
    BIO*        bio_out;

    /*
     * Using the default key length of 16 (represented by RC5_32_KEY_LENGTH).
     * The maximum length is 255 
     */
    static unsigned char key_data[RC5_32_KEY_LENGTH] = {
        0x52,0x69,0xf1,0x49,0xd4,0x1b,0xa0,0x15,
        0x24,0x97,0x57,0x4d,0x7f,0x15,0x31,0x25
    };

    unsigned char   encrypted_data[RC5_32_BLOCK];
    unsigned char   decrypted_data[RC5_32_BLOCK];

    /* Open SSL's RC5 ECB encrypt/decrypt function only handles 8 bytes of data */
    char* data_to_encrypt = "8 Bytes.";

    /* set the key structure using the predefined key */
    RC5_32_set_key(&key, RC5_32_KEY_LENGTH, key_data, RC5_12_ROUNDS);

    RC5_32_ecb_encrypt(data_to_encrypt, encrypted_data, &key, RC5_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < RC5_32_BLOCK; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)encrypted_data)[i]);

    BIO_printf(bio_out, "\n");

    /* start the decryption process */
    RC5_32_ecb_encrypt(encrypted_data, decrypted_data, &key, RC5_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < RC5_32_BLOCK; i++)
        BIO_printf(bio_out, "%c", ((unsigned char*)decrypted_data)[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
   
    return 0;

}
