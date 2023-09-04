package com.van.utils;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

/**
 * Copyright (C), 2010-2021
 * Description：
 *
 * @author fangliu
 * @version 1.0.0
 * @date 2021/10/28 14:54
 */
public class Sm4Utils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String ENCODING = "UTF-8";

    public static final String ALGORITHM_NAME = "SM4";

    // 加密算法/分组加密模式/分组填充方式
    // PKCS5Padding-以8个字节为一组进行分组加密
    // 定义分组加密模式使用：PKCS5Padding
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";

    // 128-32位16进制；256-64位16进制
    public static final int DEFAULT_KEY_SIZE = 128;

    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    public static String encryptEcb(byte[] hexKey, String paramStr) throws Exception {
        String cipherText = null;
        byte[] keyData = hexKey;
        byte[] srcData = paramStr.getBytes(ENCODING);
        byte[] cipherArray = encrypt_Ecb_Padding(keyData, srcData);
        cipherText = Base64.getEncoder().encodeToString(cipherArray);
        return cipherText;
    }

    public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static String decryptEcb(byte[] hexKey, String cipherText) throws Exception {
        String decryptStr = "";
        byte[] keyData = hexKey;
        byte[] cipherData = Base64.getDecoder().decode(cipherText);
        byte[] srcData = decrypt_Ecb_Padding(keyData, cipherData);
        decryptStr = new String(srcData, ENCODING);
        return decryptStr;
    }

    public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static boolean verifyEcb(byte[] hexKey, String cipherText, String paramStr) throws Exception {
        boolean flag = false;
        byte[] keyData = hexKey;
        byte[] cipherData = Base64.getDecoder().decode(cipherText);
        byte[] decryptData = decrypt_Ecb_Padding(keyData, cipherData);
        byte[] srcData = paramStr.getBytes(ENCODING);
        flag = Arrays.equals(decryptData, srcData);
        return flag;
    }

    public static void main(String[] args) throws Exception {
        String data = "QRCodeType=13;PId=A34013145205069578a42d548029d49cc75b4fe351a;TId=A34013145204a54c00ebcd04ba8adf44b868c505b6e;ServiceCode=10";
        byte[] keys = "NAQELBQAwXTELMAk".getBytes(StandardCharsets.UTF_8);
        byte[] bytes = encrypt_Ecb_Padding(keys, data.getBytes());
        String encryStr=new String(bytes,StandardCharsets.UTF_8);
        System.out.println(encryStr);
        Encoder encoder = Base64.getEncoder();
        String encode = encoder.encodeToString(bytes);
        System.out.println("加密结果2：" + encode);
        Decoder decoder = Base64.getDecoder();
        String decrypt = new String(decrypt_Ecb_Padding(keys, decoder.decode(encode)));
        System.out.println("解密结果2：" + decrypt);
    }
}