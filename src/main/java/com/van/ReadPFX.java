package com.van;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import sun.misc.BASE64Encoder;


public class ReadPFX {
    public ReadPFX (){
    }



    //解析PFX文件获取私钥
    private static  PrivateKey GetPvkformPfx(String strPfx, String strPassword){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(strPfx);
            // If the keystore password is empty(""), then we have to set
            // to null, otherwise it won't work!!!
            char[] nPassword = null;
            if ((strPassword == null) || strPassword.trim().equals("")){
                nPassword = null;
            }
            else
            {
                nPassword = strPassword.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();
//            System.out.println("keystore type=" + ks.getType());
            // Now we loop all the aliases, we need the alias to get keys.
            // It seems that this value is the "Friendly name" field in the
            // detals tab <-- Certificate window <-- view <-- Certificate
            // Button <-- Content tab <-- Internet Options <-- Tools menu
            // In MS IE 6.
            Enumeration enumas = ks.aliases();
            String keyAlias = null;
            if (enumas.hasMoreElements())// we are readin just one certificate.
            {
                keyAlias = (String)enumas.nextElement();
//                System.out.println("alias=[" + keyAlias + "]");
            }
            // Now once we know the alias, we could get the keys.
//            System.out.println("is key entry=" + ks.isKeyEntry(keyAlias));
            PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, nPassword);
            Certificate cert = ks.getCertificate(keyAlias);
            PublicKey pubkey = cert.getPublicKey();
//            System.out.println("cert class = " + cert.getClass().getName());
//            System.out.println("cert = " + cert);
//            System.out.println("public key = " + pubkey.getEncoded());
//            System.out.println("private key = " + prikey);
            BASE64Encoder encoder=new BASE64Encoder();
            String priavate=encoder.encode(prikey.getEncoded());
            String publicKey=encoder.encode(pubkey.getEncoded());
            System.out.println("private:"+priavate);
            System.out.println("publicKey:"+publicKey);


            return prikey;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }


    //转换成十六进制字符串
    public static String Byte2String(byte[] b) {
        String hs="";
        String stmp="";

        for (int n=0;n<b.length;n++) {
            stmp=(java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length()==1) hs=hs+"0"+stmp;
            else hs=hs+stmp;
            //if (n<b.length-1)  hs=hs+":";
        }
        return hs.toUpperCase();
    }


    //转换成字节
    public static byte[] StringToByte(int number) {
        int temp = number;
        byte[] b=new byte[4];
        for (int i=b.length-1;i>-1;i--){
            b[i] = new Integer(temp&0xff).byteValue();//将最高位保存在最低位
            temp = temp >> 8; //向右移8位
        }
        return b;
    }

    public static void main(String[] args) {
        GetPvkformPfx("D://hlht_test.pfx","12345678");
    }



}

