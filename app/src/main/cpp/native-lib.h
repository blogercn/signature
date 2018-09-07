//
// Created by user on 2018/9/4.
//

#ifndef SIGNATUREVERIFICATIONDEMO_MASTER_NATIVE_LIB_H
#define SIGNATUREVERIFICATIONDEMO_MASTER_NATIVE_LIB_H
#include <android/log.h>
#define TAG "SignatrueVerification"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG , TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO , TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN , TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR , TAG, __VA_ARGS__)
#endif //SIGNATUREVERIFICATIONDEMO_MASTER_NATIVE_LIB_H
