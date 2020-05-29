#pragma once
#include <stdio.h>

//void AES_Encrypt(unsigned char *data, unsigned int size, unsigned char *key);
//void AES_Decrypt(unsigned char *data, unsigned int size, unsigned char *key);

void AESEncryptEcb(FILE *in, FILE *out, unsigned char *key);
void AESDecryptEcb(FILE *in, FILE *out, unsigned char *key);

void AESEncryptCbc(FILE *in, FILE *out, unsigned char *key);
void AESDecryptCbc(FILE *in, FILE *out, unsigned char *key);

void AESEncryptCfb(FILE *in, FILE *out, unsigned char *key);
void AESDecryptCfb(FILE *in, FILE *out, unsigned char *key);
