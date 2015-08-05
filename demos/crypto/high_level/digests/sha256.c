#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#define DATA_LENGTH 20

int main(void)
{

	EVP_MD_CTX		mdctx;
	const EVP_MD*	md;
	BIO*			bio_out;

	int				digest_length;
	unsigned char   digest[EVP_MAX_MD_SIZE];

	int			i = 0;
    char*       data_to_hash = "The worthwhile problems are the ones you can"
                               "really solve or help solve, the ones you can"
                               "really contribute something to. ... No "
                               "problem is too small or too trivial if we "
                               "can really do something about it."
                               "- Richard Feynman";

	int			length = strlen(data_to_hash);

	OpenSSL_add_all_digests();
	
	/* retrieve the EVP_MD digest structure for SHA256 */
	md = EVP_get_digestbyname("sha256");

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);

    /*
     * For example's sake, digest the message at DATA_LENGTH bytes at a time. 
     * In reality you can simply call EVP_DigestUpdate with the full length 
     * of the message (if it's known) 
     */ 
    while (i < length)
    {
	    if ((length - i) < DATA_LENGTH)
            EVP_DigestUpdate(&mdctx, data_to_hash + i, length - i);
        else
            EVP_DigestUpdate(&mdctx, data_to_hash + i, DATA_LENGTH);

        i += DATA_LENGTH;
    }

	EVP_DigestFinal_ex(&mdctx, digest, &digest_length);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    for (i = 0; i < digest_length; i++)
        BIO_printf(bio_out, "%02x", ((unsigned char*)digest)[i]);


	BIO_printf(bio_out, "\n");

    return 0;
}
