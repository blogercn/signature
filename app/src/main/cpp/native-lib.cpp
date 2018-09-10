#include <jni.h>
#include <string>
#include "assert.h"

#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include"valid.h"
#include "MD5.h"
#include "native-lib.h"
#include "DES.h"
//签名KEY
extern const char *app_sha1;

/**
 * JNI映射
 */
extern "C"
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    jint result = -1;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    assert(env != NULL);
    jclass activityThread = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThread = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject at = env->CallStaticObjectMethod(activityThread, currentActivityThread);
    //获取Application，也就是全局的Context
    jmethodID getApplication = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
    jobject context = env->CallObjectMethod(at, getApplication);
    char *sha1 = getSha1(env, context);
    /*
    if (!checkValidity(env, sha1)) {
        return JNI_VERSION_1_4;
    }
    else{
        return JNI_ERR;
    }
     */
    /* success -- return valid version number */
    result = JNI_VERSION_1_4;

    return result;
}

/**
 *   获取存储的签名
 */
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getSignaturesSha1(
        JNIEnv *env,
        jobject,
        jobject contextObject) {

    return env->NewStringUTF(app_sha1);
}

/**
 * 签名校验
 */
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_ushaqi_zhuishushenqi_signture_checkSha1(
        JNIEnv *env,
        jobject,
        jobject contextObject) {

    char *sha1 = getSha1(env, contextObject);

    jboolean result = checkValidity(env, sha1);
    if (sha1 != NULL) {
        delete (sha1);
    }
    return result;
}

/**
 * 签名校验
 */
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getToken(
        JNIEnv *env,
        jobject,
        jobject contextObject,
        jstring userId) {
    char *sha1 = getSha1(env, contextObject);
    jboolean result = checkValidity(env, sha1);

    if (result) {
        return env->NewStringUTF("获取Token成功");
    } else {
        return env->NewStringUTF("获取失败，请检查valid.cpp文件配置的sha1值");
    }
}

/**
 * 获取MD5校验码
 */
extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_getMd5(
        JNIEnv *env,
        jobject,
        jstring strText
) {
    char *szText = (char *) env->GetStringUTFChars(strText, 0);

    MD5_CTX context = {0};
    MD5Init(&context);
    MD5Update(&context, (unsigned char *) szText, strlen(szText));
    unsigned char dest[16] = {0};
    MD5Final(&context, dest);
    env->ReleaseStringUTFChars(strText, szText);

    int i = 0;
    char szMd5[32] = {0};
    for (i = 0; i < 16; i++) {
        sprintf(szMd5, "%s%02x", szMd5, dest[i]);
    }

    return env->NewStringUTF(szMd5);
}

/**
 *读取assets文件内容
 */
extern "C"
JNIEXPORT void JNICALL
Java_com_ushaqi_zhuishushenqi_signture_readFromAssets(JNIEnv *env, jclass type,
                                                      jobject assetManager, jstring filename_)
{
    LOGW("ReadAssets");
    AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);
    if(mgr==NULL)
    {
        LOGI(" %s","AAssetManager==NULL");
        return ;
    }
    jboolean iscopy;
    const char *mfile = env->GetStringUTFChars(filename_, &iscopy);
    AAsset* asset = AAssetManager_open(mgr, mfile,AASSET_MODE_UNKNOWN);
    env->ReleaseStringUTFChars(filename_, mfile);
    if(asset==NULL)
    {
        LOGI(" %s","asset==NULL");
        return ;
    }
    off_t bufferSize = AAsset_getLength(asset);
    //LOGI("file size : %d\n",bufferSize);
    char *buffer=(char *)malloc(bufferSize+1);
    buffer[bufferSize]=0;
    int numBytesRead = AAsset_read(asset, buffer, bufferSize);
    LOGI(": %s",buffer);
    LOGW(">>>>>>>>>>>>>>>>>>>assets=%s", buffer);
    LOGW(">>>>>>>>>>>>>>>>>>>assets=%d", numBytesRead);
    free(buffer);
    AAsset_close(asset);
}

extern "C"
JNIEXPORT jbyte * JNICALL
Java_com_ushaqi_zhuishushenqi_signture_Hex2Byte(JNIEnv *env, jclass type, jstring str, jint len){
    const char *src = env->GetStringUTFChars(str, 0);
    unsigned char *des  = (unsigned char *) malloc((len/2)+1);
    HexStrToByte(src, des, len);
    des[(len/2)] = 0x00;
    env->ReleaseStringUTFChars(str, src);
    jbyteArray retArr = env->NewByteArray((len/2)+1);
    env->SetByteArrayRegion(retArr, 0, (len/2)+1, (const jbyte *) des);
    jbyte * ret = env->GetByteArrayElements(retArr, 0);
    free(des);
    return ret;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_ushaqi_zhuishushenqi_signture_Byte2Hex(JNIEnv *env, jclass type, jbyteArray bytes, jint len){
    const char *src = (char *)env->GetByteArrayElements(bytes, 0);
     char * des = ( char *) malloc((len * 2) + 1);
    ByteToHexStr((unsigned char*)src, des, len);
    env->ReleaseByteArrayElements(bytes, (jbyte*)src, 0);
    jstring ret = env->NewStringUTF(des);
    free(des);
    return ret;
}

extern "C"
 JNIEXPORT jstring JNICALL
 Java_com_ushaqi_zhuishushenqi_signture_des_1Decrypt(JNIEnv *env, jclass type, jbyteArray bytes_,
                                                     jint len) {
     jbyte *bytes = env->GetByteArrayElements(bytes_, NULL);
     int des_len=0;
     char * des = DES_Decrypt((char *) bytes, len, "abcdefg", &des_len);
     env->ReleaseByteArrayElements(bytes_, bytes, 0);

     return env->NewStringUTF(des);
 }

extern "C"
 JNIEXPORT jbyte* JNICALL
 Java_com_ushaqi_zhuishushenqi_signture_des_1Encrypt(JNIEnv *env, jclass type, jstring str_,
                                                     jint len) {
     const char *str = env->GetStringUTFChars(str_, 0);
     char  * des = ( char *) malloc((len * 2) + 1);
     HexStrToByte(str, (unsigned char *) des, len);
     env->ReleaseStringUTFChars(str_, str);
     jbyteArray arr = env->NewByteArray((len * 2) + 1);
     env->SetByteArrayRegion(arr, 0, (len * 2) + 1, ( jbyte *) des);
     jbyte* ret = env->GetByteArrayElements((jbyteArray) des, 0);//env->NewStringUTF(des);
     free(des);
     return ret;
 }
extern "C"
 JNIEXPORT jboolean JNICALL
 Java_com_ushaqi_zhuishushenqi_signture_isMd5Check(JNIEnv *env, jclass type, jobject contextObject) {
     char * cc = "com/ushaqi/zhuishushenqi/signture";
     jclass cls = env->FindClass(cc);
     jmethodID mothod =  env->GetStaticMethodID(cls, "isVerification", "(Landroid/content/Context;)Z");
     jboolean result = (jboolean) env->CallStaticBooleanMethod(cls, mothod, contextObject);
     LOGI("jiaABC>>>>>>>>>>>>>>>>>>>--------------------result=%d", result);
     char *sha1 = getSha1(env, contextObject);
     jboolean bSignature = checkValidity(env, sha1);
     if (sha1 != NULL) {
         delete (sha1);
     }
     LOGI("jiaABC>>>>>>>>>>>>>>>>>>>--------------------bSignature=%d", bSignature);
     jmethodID dlg1 =  env->GetStaticMethodID(cls, "ErrorDialog", "(Landroid/content/Context;)V");
     jmethodID dlg2 =  env->GetStaticMethodID(cls, "RightDialog", "(Landroid/content/Context;)V");
     if (result && bSignature) {
         env->CallStaticVoidMethod(cls, dlg2, contextObject);
     }else{
         env->CallStaticVoidMethod(cls, dlg1, contextObject);
     }
     return result && bSignature;
 }
extern "C"
 JNIEXPORT void JNICALL
 Java_com_ushaqi_zhuishushenqi_signture_showDialog(JNIEnv *env, jclass type, jobject context,
                                                   jboolean isRigh) {


 }
extern "C"
JNIEXPORT void JNICALL
Java_com_ushaqi_zhuishushenqi_signture_show(JNIEnv *env, jobject thiz, jobject context,
                                            jstring cstr) {
    jclass jc_Toast = env->FindClass("android/widget/Toast");
    jmethodID jm_makeText = env->GetStaticMethodID(jc_Toast, "makeText",
                                                   "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;");
    jobject jo_Toast = env->CallStaticObjectMethod(jc_Toast, jm_makeText, context, cstr, 0);
    jmethodID jm_Show = env->GetMethodID(jc_Toast, "show", "()V");
    env->CallVoidMethod(jo_Toast, jm_Show);
}

