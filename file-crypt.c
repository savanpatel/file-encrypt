#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
typedef struct KEY_IV {
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} KEY_IV;

void init() {
  /* Initialize digests table */
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
}

void getPasswordHash(char *password, unsigned char **hash, unsigned int *hashlen) {
  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  char input[] = "md5";
  unsigned char output[EVP_MAX_MD_SIZE];
  unsigned int i;
  md = EVP_get_digestbyname("MD5");
  if(!md) {
    printf("Unable to init MD5 digest\n");
    exit(1);
  }

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, password, strlen(password));
  /* to add more data to hash, place additional calls to EVP_DigestUpdate here */
  EVP_DigestFinal_ex(&mdctx, output, hashlen);
  EVP_MD_CTX_cleanup(&mdctx);

  /* Now output contains the hash value, output_len contains length of output, which is 128 bit or 16 byte in case of MD5 */

  printf("Digest is: ");
  for(i = 0; i < *hashlen; i++) printf("%03u ", output[i]);
  printf("\n %d hash len\n", *hashlen);

  *hash = output;
  printf("Address of output is %p\n", output);
}

int verifyPassword(char *password, char *fileName) {

  EVP_MD_CTX mdctx;
  const EVP_MD *md;
  char input[] = "md5";
  unsigned char output[EVP_MAX_MD_SIZE];
  unsigned int output_len, i;
  md = EVP_get_digestbyname("MD5");
  if(!md) {
    printf("Unable to init MD5 digest\n");
    exit(1);
  }

  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, md, NULL);
  EVP_DigestUpdate(&mdctx, password, strlen(password));
  /* to add more data to hash, place additional calls to EVP_DigestUpdate here */
  EVP_DigestFinal_ex(&mdctx, output, &output_len);
  EVP_MD_CTX_cleanup(&mdctx);

  /* Now output contains the hash value, output_len contains length of output, which is 128 bit or 16 byte in case of MD5 */

  printf("Digest is: ");
  for(i = 0; i < output_len; i++) printf("%02x", output[i]);
  printf("\n %d output len\n", output_len);
  /**
    perform md5 hash of password and compare to the stored password in file.
   **/
   return 0;
}

/**
   encrypt the given sourceFile and send output to outFile
   return 1 if successful, 0 otherwise.
 */
int encryptFile(char *password, char *sourceFilePath, char *outFilePath) {
  FILE *outFile = fopen(outFilePath, "w+");
  unsigned char *passwordHashFromFile = (unsigned char *) malloc(17 * sizeof(unsigned char));
  memset(passwordHashFromFile, '\0', 17 * sizeof(unsigned char));

  unsigned char *passwordCopy = (unsigned char *) malloc(17 * sizeof(unsigned char));
  memset(passwordCopy, '\0', 17 * sizeof(unsigned char));

  printf("Encrypting file %s\n", sourceFilePath);

  unsigned char *passwordHash = NULL;
  unsigned int passwordHashLen;

  getPasswordHash(password, &passwordHash, &passwordHashLen);


  for(unsigned int i = 0; i < passwordHashLen; i++){
    passwordCopy[i] = passwordHash[i];
    //printf(" %03u ", passwordHash[i]);
  }


  printf("\n");
  for(unsigned int i = 0; i < passwordHashLen; i++){
    fprintf(outFile, "%03u ", passwordCopy[i]);
  }

  fseek(outFile, 0L, SEEK_SET);

  printf("\n");
  for(unsigned int i = 0; i < passwordHashLen; i++) {
    unsigned int fromFile;
    fscanf(outFile, "%03u ", &fromFile);
    printf("%03u ", fromFile);
    if (fromFile != passwordCopy[i]) {
      printf("Not equal\n");
      return 0;
    }
  }

  printf("Equal Yay!\n");

  return 0;
}

/**
  decrypt the given file after verifying password.
 */
int decryptFile(char *password, char *sourceFile, char *outFile) {
  return 0;
}

KEY_IV * generateKeyIV(const char *password) {
  const EVP_CIPHER *cipher;
  const EVP_MD *dgst = NULL;
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
  KEY_IV *key_iv = (KEY_IV *) malloc( 1 * sizeof(KEY_IV));
  if (NULL == key_iv) {
    fprintf(stderr, "Failed to allocated bytes for key iv. \n");
    return NULL;
  }
  const unsigned char *salt = NULL;

  cipher = EVP_get_cipherbyname("aes-256-cbc");
  if(!cipher) { fprintf(stderr, "no such cipher\n"); return NULL; }

  dgst=EVP_get_digestbyname("md5");
  if(!dgst) { fprintf(stderr, "no such digest\n"); return NULL; }

  if(!EVP_BytesToKey(cipher, dgst, salt,
      (unsigned char *) password,
      strlen(password), 1, key_iv->key, key_iv->iv))
  {
      fprintf(stderr, "EVP_BytesToKey failed\n");
      return NULL;
  }
  key_iv->key[cipher->key_len] = '\0';
  key_iv->iv[cipher->iv_len] = '\0';
  return key_iv;
}

int main(int argc, char *argv[])
{
    init();
    char *password = getpass("Password:");
    char *mode = argv[1];
    char *inFile = argv[2];
    char *outFile = argv[3];

    printf("mode: %s, inFile %s, outFile: %s\n", mode, inFile, outFile );
    KEY_IV *key_iv = generateKeyIV(password);

    if(strcmp(mode, "ENCRYPT") == 0) {
      encryptFile(password, inFile, outFile);
    } else if (strcmp(mode, "DECRYPT") == 0) {
      /* decrypt */
    } else {
      fprintf(stderr, "Incorrect operation mode Supported are {ENCRYPT, DECRYPT}");
      exit(1);
    }

    return 0;
}
