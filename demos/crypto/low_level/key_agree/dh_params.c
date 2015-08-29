#include <stdio.h>
#include <openssl/dh.h>
#include <openssl/err.h>


#define PRIME_LENGTH    2048

int main(void)
{
    DH* dh_store;
    int codes;

    // Allocate and initialize a DH structure
    dh_store = DH_new();

    // If allocation failed
    if (dh_store == NULL)
    {
        fprintf(stderr, "Error allocating DH structure.\n");
        fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }


    // Generate the prime, and and initialize the generator to be used for this exchange
    if (DH_generate_parameters_ex(dh_store, PRIME_LENGTH, DH_GENERATOR_2, NULL) != 1)
    {
        fprintf(stderr, "Error allocating parameters.\n");
        fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }


    // Validate the generated prime (p) and the supplied generator (g).
    if (!DH_check(dh_store, &codes))
    {
        fprintf(stderr, "Could not perform check.\n");
        fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }
    

    // Examine the results of the check performed earlier.
    if (codes != 0)
    {
        // Check and print out what kind of error was identified.
        if (codes & DH_UNABLE_TO_CHECK_GENERATOR)
            fprintf(stderr, "Generator must be either 2 or 5.\n");
        else if (codes & DH_NOT_SUITABLE_GENERATOR)
            fprintf(stderr, "Generator is not suitable.\n");
        else if (codes & DH_CHECK_P_NOT_PRIME)
            fprintf(stderr, "Non-prime value found in structure.");
        else if (codes & DH_CHECK_P_NOT_SAFE_PRIME)
            fprintf(stderr, "Unsafe prime found in structure.\n");
        else
            fprintf(stderr, "Unknown error.\n");
     
        fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));

        return 1;
    }


    // Generate the private value (aka private key) and the 
    // public value (aka public key).
    if (!DH_generate_key(dh_store))
    {
        fprintf(stderr, "Error generating public and private keys.");
        fprintf(stderr, "%s", ERR_reason_error_string(ERR_get_error()));        

        return 1;
    }

    printf("Generator:\n");
    BN_print_fp(stdout, dh_store->g);
    printf("\n\n");
    printf("Prime:\n");
    BN_print_fp(stdout, dh_store->p);
    printf("\n\n");
    printf("Private key:\n");
    BN_print_fp(stdout, dh_store->priv_key);
    printf("\n\n");
    printf("Public key:\n");
    BN_print_fp(stdout, dh_store->pub_key);
    printf("\n\n");

    // Free the DH structure.
    DH_free(dh_store);

    return 0;
}
