#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

typedef struct KEY_IV {
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} KEY_IV;

int verifyPassword(password, fileName) {
  /**
    perform md5 hash of password and compare to the stored password in file.
   **/
   return 0;
}

/**
   encrypt the given sourceFile and send output to outFile
   return 1 if successful, 0 otherwise.
 */
int encrypt(password, sourceFile, outFile) {

  return 0;
}

/**
  decrypt the given file after verifying password.
 */
int decrypt(password, sourceFile, outFile) {
  return 0;
}


char * readPassword() {
  return "password";
}
int main(int argc, char *argv[])
{
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *password = readPassword();
    const unsigned char *salt = NULL;
    int i;

    OpenSSL_add_all_algorithms();

    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if(!cipher) { fprintf(stderr, "no such cipher\n"); return 1; }

    dgst=EVP_get_digestbyname("md5");
    if(!dgst) { fprintf(stderr, "no such digest\n"); return 1; }

    if(!EVP_BytesToKey(cipher, dgst, salt,
        (unsigned char *) password,
        strlen(password), 1, key, iv))
    {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02x", key[i]); } printf("\n");
    printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02x", iv[i]); } printf("\n");

    return 0;
}
