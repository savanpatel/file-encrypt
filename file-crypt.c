#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

//TODO: in separate header file.
typedef struct KEY_IV {
  unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} KEY_IV;

KEY_IV * generateKeyIV(const char *password);

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

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encryptText(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,unsigned char *iv,
                unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

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
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}


int decryptText(unsigned char *ciphertext, int ciphertext_len,
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
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
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
  FILE *outFile = fopen(outFilePath, "w+");
  FILE *sourceFile = fopen(sourceFilePath, "r");
  //unsigned char *passwordHashFromFile = (unsigned char *) malloc(17 * sizeof(unsigned char));
  //memset(passwordHashFromFile, '\0', 17 * sizeof(unsigned char));

  unsigned char *passwordCopy = (unsigned char *) malloc(17 * sizeof(unsigned char));
  memset(passwordCopy, '\0', 17 * sizeof(unsigned char));
  unsigned char *passwordHash = NULL;
  unsigned int passwordHashLen;

  printf("Encrypting file %s\n", sourceFilePath);

  getPasswordHash(password, &passwordHash, &passwordHashLen);

  // TODO: comment for potential better way.
  for(unsigned int i = 0; i < passwordHashLen; i++){
    passwordCopy[i] = passwordHash[i];
  }


  // TODO: remove.
  printf("\n");
  for(unsigned int i = 0; i < passwordHashLen; i++){
    fprintf(outFile, "%03u ", passwordCopy[i]);
  }

  //fprintf(outFile, "\n");

  // encrypt chunks of 80 chars.
  //TODO: remove following crap.
  char *plaintext = "Savan";
  unsigned char *ciphertext = (unsigned char *) malloc(100 * sizeof(unsigned char));
  KEY_IV *key_iv = generateKeyIV(password);
  int len = encryptText((unsigned char *)plaintext, 5, key_iv->key, key_iv->iv, ciphertext);

  printf("\n plaintext: %s\n", plaintext);
  printf("ciphertext: %s\n", ciphertext);

  unsigned char *plaintextdec = (unsigned char *) malloc(5 * sizeof(unsigned char));
  len = decryptText(ciphertext, len,
                    key_iv->key, key_iv->iv,
                    plaintextdec);
  plaintextdec[len] = '\0';
  printf("\n Decrypted text: %s, len %d \n", plaintextdec, len);

  // read file 80 chars each.
  char data[81];
  memset(data, '\0', 81);
  int encryptlen = 0;
  while ((len = fread(data, 1, 80, sourceFile)) != 0) {
    if (len == 0) {
      printf("I AM DONE\n");
      break;
    }
    encryptlen = encryptText((unsigned char *)data, strlen(data),
                             key_iv->key, key_iv->iv, ciphertext);
    printf("encryptlen is %d\n", encryptlen);
    fprintf(outFile, "%03d ", encryptlen);
    for (unsigned int i = 0; i < encryptlen; i++) {
      fprintf(outFile, "%03u ", ciphertext[i]);
    }
    memset(data, '\0', 81);
  }
  // TODO:remove
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
  printf("-----------------\n");
  while (1) {
    int encryptedlen;
    int success = fscanf(outFile, "%03d ", &encryptedlen);
    printf("encryptedlen is %d \n", encryptedlen);
    if (!success) {
      break;
    }

    unsigned char *encryptedText = (unsigned char *) malloc((encryptedlen+1)*sizeof(unsigned char));
    for (unsigned int i = 0; i < encryptedlen; i++) {
      unsigned int u;
      fscanf(outFile, "%03u ", &u);
      printf("read... %03u\n", u);
      encryptedText[i] = (unsigned char)u;
    }
    char plaintext1[81];
    memset(plaintext1, '\0', 81);
    decryptText((unsigned char *)encryptedText, encryptedlen,
                key_iv->key, key_iv->iv,
                (unsigned char *)plaintext1);
    printf("From decrypt: %s", plaintext1);
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
