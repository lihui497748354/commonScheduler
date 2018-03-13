package com.effort.encryption;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.SecureRandom;

public class ThreeDES {

    //定义加密算法,可用 DES,DESede,Blowfish
    private static final String Algorithm = "DESede";


    private String threeDES(String str){
        try {
            // 生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(Algorithm);
            //SecureRandom()
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytes = secretKey.getEncoded();

            //Key转化
            DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(bytes);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(Algorithm);
            Key convertKey = factory.generateSecret(deSedeKeySpec);

            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertKey);
            byte[] result = cipher.doFinal(str.getBytes());
            System.out.println("jia mi : "+HexBin.encode(result));

            //
            cipher.init(Cipher.DECRYPT_MODE,convertKey);
            result = cipher.doFinal(result);
            System.out.println("jie mi : "+new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
         new ThreeDES().threeDES("hello effort this is 3des");
    }
}
