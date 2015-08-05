#include <stdio.h>
#include <string.h>
#include <openssl/rc2.h>
#include <openssl/bio.h>



int main(void)
{
    int     i;
    RC2_KEY key;
    BIO*    bio_out;

    static unsigned char RC2Key[RC2_KEY_LENGTH] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    };

    unsigned char   encrypted_data[RC2_BLOCK];
    unsigned char   decrypted_data[RC2_BLOCK];

    /* Open SSL's RC2 ECB encrypt/decrypt function only handle 8 bytes of data */
    char* data_to_encrypt = "8 Bytes.";

    /* set the key structure using the (unmodified) predefined key */
    RC2_set_key(&key, RC2_KEY_LENGTH, RC2Key, 1024);
    RC2_ecb_encrypt(data_to_encrypt, encrypted_data, &key, RC2_ENCRYPT);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(bio_out, "Original plaintext: %s\n", data_to_encrypt);

    BIO_printf(bio_out, "Ciphertext: ");

    /* print out the ciphertext */
    for (i = 0; i < RC2_BLOCK; i++)
        BIO_printf(bio_out, "%02x", (unsigned char*)encrypted_data[i]);

    BIO_printf(bio_out, "\n");

    /* start the decryption process */
    RC2_ecb_encrypt(encrypted_data, decrypted_data, &key, RC2_DECRYPT);

    BIO_printf(bio_out, "Recovered plaintext: ");
    
    /* print out the plaintext */
    for (i = 0; i < RC2_BLOCK; i++)
        BIO_printf(bio_out, "%c", (unsigned char*)decrypted_data[i]);

    BIO_printf(bio_out, "\n");

    BIO_free(bio_out);
   
    return 0;

}
