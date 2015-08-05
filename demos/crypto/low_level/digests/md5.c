#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/bio.h>

#define DATA_LENGTH 20

int main(void)
{
    
    MD5_CTX         context;
    unsigned char   hash[MD5_DIGEST_LENGTH];
    BIO*            bio_out;

    char*       data_to_hash = "The worthwhile problems are the ones you can"
                               "really solve or help solve, the ones you can"
                               "really contribute something to. ... No "
                               "problem is too small or too trivial if we "
                               "can really do something about it."
                               "- Richard Feynman";

    int         length = (int)strlen(data_to_hash);
    int         i      = 0;


    MD5_Init(&context);

    while (i < length)
    {
        if ((length - i) < DATA_LENGTH)
            MD5_Update(&context, (void*)(data_to_hash + i), length - i);
        else
            MD5_Update(&context, (void*)(data_to_hash + i), DATA_LENGTH);

        i += DATA_LENGTH;
    }

    MD5_Final(hash, &context);

    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    for (i = 0; i < MD5_DIGEST_LENGTH; i++)
        BIO_printf(bio_out, "%02x", (unsigned char*)hash[i]);


    return 0;

}