#include <stdio.h>
#include <string.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "Base64.h"
#define BLOCK_SIZE                 (16)                  
#define AES_KEY_SIZE               (128)                 

#define AES_FAIL (-1)
#define AES_OK (0)

static unsigned char AES_PASSWORD[] = "1234567812345678";
char g_iv_enc[] = "1234567812345678";
char g_iv_dec[] = "1234567812345678";

static unsigned int PadData(unsigned char *ibuf, int ilen, int blksize)
{
    unsigned int i;    /* loop counter*/
    unsigned char pad; /* pad character (calculated)*/
    unsigned char *p;  /*pointer to end of data*/

    if (0 == (ilen % blksize))
    {
        return ilen;
    }

    pad = (unsigned char)(blksize - (ilen % blksize));

    p = ibuf + ilen;
    for (i = 0; i < (int) pad; i++)
    {
        *p = 0x00;
        ++p;
    }

    return (ilen + pad);
}
int _encrypt(char *pSrc, unsigned char *pDstEncryptData, int n_pDstEncryptData)
{
    int dwRet = AES_OK;
    int dwLengthInPad = 0;
    unsigned char *pOut = NULL;
    unsigned char *base64EncodeOutput = NULL;
    AES_KEY tAeskey;
    unsigned char *pSrcPadBuffer = NULL;

    if ((NULL == pSrc) || (NULL == pDstEncryptData))
    {
        return AES_FAIL;
    }

    pSrcPadBuffer = (unsigned char *)calloc(1, strlen(pSrc) + BLOCK_SIZE);
    if (NULL == pSrcPadBuffer)
    {
        return AES_FAIL;
    }
    memcpy(pSrcPadBuffer, pSrc, strlen(pSrc));


    dwLengthInPad = PadData(pSrcPadBuffer, strlen(pSrc), BLOCK_SIZE);
    printf("AES KEY: %s\n", AES_PASSWORD);
    dwRet = AES_set_encrypt_key(AES_PASSWORD, AES_KEY_SIZE, &tAeskey);
    if (AES_OK != dwRet)
    {
        free(pSrcPadBuffer);
        return AES_FAIL;
    }

    pOut = (unsigned char *)calloc(dwLengthInPad, sizeof(unsigned char));
    if (NULL == pOut)
    {
        free(pSrcPadBuffer);
        return AES_FAIL;
    }

    printf("AES IV: %s\n", g_iv_enc);
    AES_cbc_encrypt(pSrcPadBuffer, pOut, dwLengthInPad, &tAeskey, g_iv_enc, AES_ENCRYPT);
    Base64Encode(pOut, &base64EncodeOutput);
    printf("Output (base64): %s\n", base64EncodeOutput);

    if (NULL == base64EncodeOutput)
    {
        free(pOut);
        free(pSrcPadBuffer);
        return AES_FAIL;
    }
    snprintf(pDstEncryptData, n_pDstEncryptData, "%s", base64EncodeOutput);

    free(pSrcPadBuffer);
    free(pOut);
    free(base64EncodeOutput);

    return dwRet;
}

int _decrypt(const char *pSrc, unsigned char *pDstDecryptData, int n_pDstDecryptData)
{
    int dwRet = AES_OK;
    AES_KEY tAeskey;

    if ((NULL == pSrc) || (NULL == pDstDecryptData))
    {
        return AES_FAIL;
    }
    char* base64DecodeOutput = NULL;
    int base64DecodeLen = Base64Decode(pSrc, &base64DecodeOutput);

    dwRet = AES_set_decrypt_key(AES_PASSWORD, AES_KEY_SIZE, &tAeskey);
    printf("AES KEY: %s\n", AES_PASSWORD);
    if (AES_OK != dwRet)
    {
        return AES_FAIL;
    }
    printf("AES IV: %s\n", g_iv_dec);
    AES_cbc_encrypt(base64DecodeOutput, pDstDecryptData, base64DecodeLen, &tAeskey, g_iv_dec, AES_DECRYPT);
    free(base64DecodeOutput);
    return dwRet;
}

int main(int argc, char **argv)
{
    if ( argc <= 1 || argc > 2){
        printf("usage:\n");
        printf("    %s plaintext\n", argv[0]);
        return -1;
    }
    unsigned char pDstEncryptData[128] = {0};
    unsigned char pDstDecryptData[64] = {0};

    if( AES_FAIL == _encrypt(argv[1], pDstEncryptData, sizeof(pDstEncryptData))){
        printf("fail encrypt\n");
        return -1;
    }
    printf("encrypt result: %s\n", pDstEncryptData);

    if( AES_FAIL == _decrypt(pDstEncryptData, pDstDecryptData, sizeof(pDstDecryptData))){
        printf("fail decrypt\n");
        return -1;
    }   
    printf("decrypt length: %d\n", strlen(pDstDecryptData));
    printf("decrypt result: %s\n", pDstDecryptData);
}



