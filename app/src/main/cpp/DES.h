//
// Created by user on 2018/9/5.
//

#ifndef SIGNATUREVERIFICATIONDEMO_MASTER_DES_H
#define SIGNATUREVERIFICATIONDEMO_MASTER_DES_H
extern "C" {
char *DES_Decrypt(char *sourceData, int sourceSize, char *keyStr, int *resultSize);
char *DES_Encrypt(char *sourceData, int sourceSize, char *keyStr, int *resultSize);
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen);
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen);
}
#endif //SIGNATUREVERIFICATIONDEMO_MASTER_DES_H
