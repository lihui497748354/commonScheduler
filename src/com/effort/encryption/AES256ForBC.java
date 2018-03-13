package com.effort.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

public class AES256ForBC {

    private static final String key = "zsyy";
    private static SecureRandom secureRandom;

    public AES256ForBC(){
        this.secureRandom = new SecureRandom(tohash256Deal(key));
    }

//    = new SecureRandom(tohash256Deal(key));



    private static byte[] encrypt(String password, String key) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            //"AES"：请求的密钥算法的标准名称
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
//            SecureRandom securerandom = new SecureRandom(tohash256Deal(key));
            kgen.init(256, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] byteContent = password.getBytes("utf-8");
            byte[] cryptograph = cipher.doFinal(byteContent);
            return Base64.encode(cryptograph);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String decrypt(byte[] cryptograph, String key) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
//            SecureRandom securerandom = new SecureRandom(tohash256Deal(key));
            kgen.init(256, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] content = cipher.doFinal(Base64.decode(cryptograph));
            return new String(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String parseByte2HexStr(byte buf[]) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            stringBuffer.append(hex.toUpperCase());
        }
        return stringBuffer.toString();
    }

    private static byte[] tohash256Deal(String datastr) {
        try {
            MessageDigest digester=MessageDigest.getInstance("SHA-256");
            digester.update(datastr.getBytes());
            byte[] hex=digester.digest();
            return hex;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static void main(String[] args) {

        String password = "0f607264fc6318a92b9e13c65db7cd3c";
        System.out.println("明文：" + password);
        System.out.println("key：" + key);

        byte[] encryptResult = AES256ForBC.encrypt(password, key);
        System.out.println("密文：" + AES256ForBC.parseByte2HexStr(encryptResult));

        String decryptResult = AES256ForBC.decrypt(encryptResult, key);
        System.out.println("解密：" + decryptResult);
    }
}
