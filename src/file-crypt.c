#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//TODO: in separate header file
typedef struct KEY_IV {
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} KEY_IV;

KEY_IV * generateKeyIV(const char *password);

void init() {
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_digests();
}

void getPasswordHash(char *password,
                     unsigned char **hash,
                     unsigned int *hashlen) {
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
  EVP_DigestFinal_ex(&mdctx, output, hashlen);
  EVP_MD_CTX_cleanup(&mdctx);

  *hash = output;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/*
 * Reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
int encryptText(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,unsigned char *iv,
                unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertextLen;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertextLen = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertextLen += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertextLen;
}

/*
 * Reference: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */
int decryptText(unsigned char *ciphertext, int ciphertextLen,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLen))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/**
   encrypt the given sourceFile and send output to outFile
   return 1 if successful, 0 otherwise.
 */
int encryptFile(char *password, char *sourceFilePath, char *outFilePath) {
  FILE *outFile = fopen(outFilePath, "wb+");
  FILE *sourceFile = fopen(sourceFilePath, "r");

  if (NULL == sourceFile) {
    printf("Failed to open %s. Encryption failed.\n", sourceFilePath);
  }

  if (NULL == outFile) {
    printf("Failed to open %s. Encryption failed.\n", outFilePath);
  }

  unsigned char passwordCopy[17];
  memset(passwordCopy, '\0', 17 * sizeof(unsigned char));
  unsigned char *passwordHash = NULL;
  unsigned int passwordHashLen;

  getPasswordHash(password, &passwordHash, &passwordHashLen);

  memcpy(passwordCopy, passwordHash, 16 * sizeof(unsigned char));

  int writeLen = fwrite(passwordCopy, sizeof(unsigned char), 16, outFile);

  KEY_IV *key_iv = generateKeyIV(password);
  int readLen = 0, encryptLen = 0;
  unsigned char ciphertext[100];
  char data[81];
  memset(data, '\0', 81);

  while ((readLen = fread(data, 1, 80, sourceFile)) != 0) {

    memset(ciphertext, '\0', 100 * sizeof(unsigned char));
    encryptLen = encryptText((unsigned char *)data, readLen,
                             key_iv->key, key_iv->iv, ciphertext);
    fwrite(&encryptLen, sizeof(int), 1, outFile);
    fwrite(ciphertext, sizeof(unsigned char), encryptLen, outFile);
    memset(data, '\0', 81);
  }

  fclose(outFile);
  fclose(sourceFile);
  remove(sourceFilePath);
  return 0;
}

/**
  decrypt the given file after verifying password.
 */
int decryptFile(char *password, char *sourceFilePath, char *outFilePath) {
  KEY_IV *key_iv = generateKeyIV(password);
  FILE *outFile = fopen(outFilePath, "w+");
  FILE *sourceFile = fopen(sourceFilePath, "rb");

  if (NULL == sourceFile) {
    printf("Failed to open %s. Encryption failed.\n", sourceFilePath);
  }

  if (NULL == outFile) {
    printf("Failed to open %s. Encryption failed.\n", outFilePath);
  }

  unsigned char passwordCopy[17];
  unsigned char passwordFromFile[17];
  memset(passwordCopy, '\0', 17 * sizeof(unsigned char));
  memset(passwordFromFile, '\0', 17 * sizeof(unsigned char));

  unsigned char *passwordHash = NULL;
  unsigned int passwordHashLen;

  getPasswordHash(password, &passwordHash, &passwordHashLen);

  memcpy(passwordCopy, passwordHash, 16 * sizeof(unsigned char));

  unsigned char *ciphertext = (unsigned char *) malloc(100 * sizeof(unsigned char));
  unsigned char *plaintext = (unsigned char *) malloc(81 * sizeof(unsigned char));

  fread(passwordFromFile, sizeof(unsigned char), 16, sourceFile);
  for(unsigned int i = 0; i < passwordHashLen; i++) {
    if (passwordFromFile[i] != passwordCopy[i]) {
      printf("Password does not match.\n");
      return 0;
    }
  }

  while (1) {
    int ciphertextLen = 0;
    int i = 0;
    int isDone = fread(&ciphertextLen, sizeof(int), 1, sourceFile);
    if (isDone == 0) {
      break;
    }

    fread(ciphertext, sizeof(unsigned char), ciphertextLen, sourceFile);
    ciphertext[ciphertextLen] = '\0';
    int decryptLen =
        decryptText(ciphertext, ciphertextLen, key_iv->key, key_iv->iv, plaintext);
    plaintext[decryptLen] = '\0';
    fprintf(outFile, "%s", (char *)plaintext);
  }

  fclose(sourceFile);
  fclose(outFile);
  remove(sourceFilePath);
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

void printUsage() {
  printf("Usage: ./file-crypt -e <file_to_encrypt> -o <out_file> | ");
  printf("./file-crypt -d <file_to_decrypt> -o <out_file> \n");
}

void getoptions (char **mode, char **inFile, char **outFile, int argc, char **argv) {
  char c;
  int encryptFlag = 0;
  int decryptFlag = 0;
  while((c = getopt(argc, argv, "e:d:o:")) != -1) {
    switch (c) {
      case 'e': if (encryptFlag) {
                  printUsage();
                  exit(1);
              } else {
                encryptFlag++;
                decryptFlag++;
              }
              *mode = "ENCRYPT";
              *inFile = optarg;
              break;
      case 'd': if (decryptFlag) {
                    printUsage();
                    exit(1);
                } else {
                  decryptFlag++;
                  encryptFlag++;
                }
                *mode = "DECRYPT";
                *inFile = optarg;
                break;
      case 'o':
              *outFile = optarg;
              break;
      default: printUsage();
               exit(1);
               break;
    }
  }
}
int main(int argc, char *argv[])
{
    if (argc < 4) {
      printUsage();
      exit(1);
    }
    char *mode, *inFile, *outFile;
    getoptions(&mode, &inFile, &outFile, argc, argv);
    if (outFile == NULL || inFile == NULL || mode == NULL) {
      printUsage();
      exit(1);
    }
    init();
    char *password = getpass("Password:");

    printf("mode: %s, inFile %s, outFile: %s\n", mode, inFile, outFile );
    KEY_IV *key_iv = generateKeyIV(password);

    if(strcmp(mode, "ENCRYPT") == 0) {
      encryptFile(password, inFile, outFile);
    } else if (strcmp(mode, "DECRYPT") == 0) {
      decryptFile(password, inFile, outFile);
    } else {
      fprintf(stderr, "Incorrect operation mode Supported are {ENCRYPT, DECRYPT}");
      exit(1);
    }

    return 0;
}
