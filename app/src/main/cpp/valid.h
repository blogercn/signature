//
// Created by user on 2018/9/4.
//

#ifndef SIGNATUREVERIFICATIONDEMO_MASTER_VALID_H
#define SIGNATUREVERIFICATIONDEMO_MASTER_VALID_H

#include "native-lib.h"
extern "C"{
jboolean checkValidity(JNIEnv *env,char *sha1);
char* getSha1(JNIEnv *env, jobject context_object);
}
#endif //SIGNATUREVERIFICATIONDEMO_MASTER_VALID_H
