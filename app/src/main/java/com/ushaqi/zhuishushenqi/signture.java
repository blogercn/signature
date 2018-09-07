package com.ushaqi.zhuishushenqi;

import android.app.AlertDialog;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Created by jiazhiguo(jiazg@1391.com) on 2018/8/30.
 */

public class signture {
    static {
        System.loadLibrary("native-lib");
    }

    static public native String getSignaturesSha1(Context context);
    static public native boolean checkSha1(Context context);
    static public native String getToken(Context context, String userId);
    static public native String getMd5(String mdstr);
    static public native String readFromAssets(AssetManager assetManager, String filename);
    static public native String des_Decrypt(byte[] bytes, int len);
    static public native String des_Encrypt(String str, int len);
    static public native byte[] Hex2Byte(String str, int len);
    static public native String Byte2Hex(byte[] bytes, int len);
    static public native boolean isMd5Check(Context context);
    static public native void showDialog(Context context, boolean isRigh);

    /**
     *
     * @param pi
     * @return
     */
    public static String[] getPublicKeyString(PackageInfo pi) {
        PublicKey pubKeys[] = getPublicKey(pi);
        if (pubKeys == null || pubKeys.length == 0) {
            return null;
        }
        String[] strPubKeys = new String[pubKeys.length];
        for (int i = 0; i < pubKeys.length; i++)
            strPubKeys[i] = Base64.encodeToString(pubKeys[i].getEncoded(),
                    Base64.DEFAULT);
        return strPubKeys;
    }

    /**
     *
     * @param pi
     * @return
     */
    private static PublicKey[] getPublicKey(PackageInfo pi) {
        try {
            if (pi.signatures == null || pi.signatures.length == 0) {
                return null;
            }
            PublicKey[] publicKeys = new PublicKey[pi.signatures.length];
            for (int i = 0; i < publicKeys.length; i++) {
                byte[] signature = pi.signatures[i].toByteArray();
                CertificateFactory certFactory = CertificateFactory
                        .getInstance("X.509");
                InputStream is = new ByteArrayInputStream(signature);
                X509Certificate cert = (X509Certificate) certFactory
                        .generateCertificate(is);

                publicKeys[i] = cert.getPublicKey();
            }
        } catch (Exception ex) {

        }
        return null;
    }

    public static PublicKey[] getInstalledAppPublicKey(Context context,
                                                       String packageName) {
        PackageManager pm = context.getPackageManager();
        PackageInfo pi;
        try {
            pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            if (pi != null && pi.versionName != null) {
                return getPublicKey(pi);
            }
        } catch (PackageManager.NameNotFoundException e) {
            // not installed
            return null;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry je) {
        try {
            // We must read the stream for the JarEntry to retrieve
            // its certificates.
            byte[] readBuffer = new byte[1024];
            InputStream is = jarFile.getInputStream(je);
            while (is.read(readBuffer, 0, readBuffer.length) != -1)
                ;
            is.close();

            return (je != null) ? je.getCertificates() : null;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifySignature(Context context, String packageName,
                                          String filePath) {
        boolean verifyed = true;
        try {
            PublicKey[] installedAppPubKeys = getInstalledAppPublicKey(context,
                    packageName);
            if (installedAppPubKeys == null || installedAppPubKeys.length == 0) {
                // package not installed
                return true;
            }
            JarFile jarFile = new JarFile(filePath);
            verifyed = false;
            JarEntry je = jarFile.getJarEntry("classes.dex");
            Certificate[] certs = loadCertificates(jarFile, je);
            if (certs != null && certs.length > 0) {
                for (int i = 0; i < certs.length; i++) {
                    PublicKey pubKey = certs[i].getPublicKey();
                    for (int j = 0; j < installedAppPubKeys.length; j++) {
                        if (pubKey.equals(installedAppPubKeys[j])) {
                            verifyed = true;
                            break;
                        }
                    }
                    if (verifyed)
                        break;
                }
            } else {
                verifyed = true;
            }

            jarFile.close();
        } catch (Exception e) {
            verifyed = true;
        }

        return verifyed;
    }

    /**
     * 获得证书的sha1值
     * @param context
     * @return
     */
    public String getSha1Value(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] publicKey = md.digest(cert);
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < publicKey.length; i++) {
                String appendString = Integer.toHexString(0xFF & publicKey[i])
                        .toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
            }
            String result = hexString.toString();
            return result.substring(0, result.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 计算字符串的md5值
     * @param context
     * @param str
     * @return
     */
    public String getMd5Str(Context context, String str) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] publicKey = md.digest(str.getBytes());
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < publicKey.length; i++) {
                String appendString = Integer.toHexString(0xFF & publicKey[i])
                        .toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
            }
            String result = hexString.toString();
            return result.substring(0, result.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取APK签名证书的MD5值
     * @param context
     * @return
     */
    public String getMd5Value(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] publicKey = md.digest(cert);
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < publicKey.length; i++) {
                String appendString = Integer.toHexString(0xFF & publicKey[i])
                        .toUpperCase(Locale.US);
                if (appendString.length() == 1)
                    hexString.append("0");
                hexString.append(appendString);
            }
            String result = hexString.toString();
            return result.substring(0, result.length());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 校验Dex CRC值
     */
    private long getDexCrc(Context context) {
        String apkPath = context.getPackageCodePath();
        try {
            ZipFile zipFile = new ZipFile(apkPath);
            ZipEntry dexEntry = zipFile.getEntry("classes.dex");

            //计算classes.dex的 crc
            long dexEntryCrc = dexEntry.getCrc();
            Log.d("DEX", dexEntryCrc + "");
            return dexEntryCrc;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return -1;
    }

    /**
     * 获取APK MD5值
     */
    public static String getApkMd5(Context context) {
        //获取data/app/****/base.apk 路径
        String apkPath = context.getPackageResourcePath();
        Log.d("APK", apkPath);
        MessageDigest msgDigest;
        try {
            //获取apk并计算MD5值
            msgDigest = MessageDigest.getInstance("MD5");
            byte[] bytes = new byte[4096];
            int count;
            FileInputStream fis;
            fis = new FileInputStream(new File(apkPath));

            while ((count = fis.read(bytes)) > 0) {
                msgDigest.update(bytes, 0, count);
            }
            //计算出MD5值
            BigInteger bInt = new BigInteger(1, msgDigest.digest());
            String md5 = bInt.toString(16);
            fis.close();
            Log.d("APK", md5);
            return md5;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取DEX的MD5校验值
     * @param context
     * @return
     */
    public static String getDexMd5(Context context) {
        String apkPath = context.getPackageCodePath();

        MessageDigest msgDigest;
        try {
            ZipFile zipFile = new ZipFile(apkPath) ;
            ZipInputStream zipInput = new ZipInputStream(new FileInputStream(apkPath)) ;
            ZipEntry dexEntry = null;
            while((dexEntry = zipInput.getNextEntry())!=null){	// 得到一个压缩实体
                if (dexEntry.getName().indexOf("classes.dex") != -1){
                    break;
                }
            }
            zipInput.close() ;
            //获取apk并计算MD5值
            msgDigest = MessageDigest.getInstance("MD5");
            byte[] bytes = new byte[4096];
            int count;
            InputStream fis;
            fis = zipFile.getInputStream(dexEntry);

            while ((count = fis.read(bytes)) > 0) {
                msgDigest.update(bytes, 0, count);
            }
            //计算出MD5值
            BigInteger bInt = new BigInteger(1, msgDigest.digest());
            String md5 = bInt.toString(16);
            fis.close();
            Log.d("APK", md5);
            return md5;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean isVerification(Context context) {
        String newMd5 = getDexMd5(context);
        String oldMd5 = ReadAssetsString(context);
        Log.i("jiaABC", ">>>>>>>>>>>>>>newMd5="+newMd5);
        Log.i("jiaABC", ">>>>>>>>>>>>>>oldMd5="+oldMd5);
        if (newMd5.equals(oldMd5)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * byte 转16进制字符串
     * @param b
     * @return
     */
    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs;
    }

    /**
     * 读取assets文件
     * @param context
     * @return
     */
    public static String ReadAssetsString(Context context) {
        InputStream is = null;
        String msg = null;
        try {
            is = context.getResources().getAssets().open("log.txt");
            byte[] bytes = new byte[is.available()];
            is.read(bytes);
            msg = new String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return msg;
    }

    public static void ErrorDialog(Context context){
            new AlertDialog.Builder(context)
                    .setTitle("错误")
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .setMessage("破解版被禁用，请使用正版")
                    .setPositiveButton("确定", null)
                    .show();

    }
    public static void RightDialog(Context context){
            new AlertDialog.Builder(context)
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .setTitle("正确")
                    .setMessage("签名正常")
                    .setPositiveButton("确定", null)
                    .show();
    }

}
