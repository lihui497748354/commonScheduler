package com.effort.encryption;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;

public class AES256ForBC {
    private static final String ALGORITHM = "AES";
    /**
     * 获取初始化之后的Cipher对象
     *
     * @param mode
     *          加密/解密
     * @param key
     *             key
     * @return
     *          初始化之后的Cipher对象
     */
    private Cipher getCipher(int mode,String key){
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            //SecureRandom 实现完全隨操作系统本身的内部状态，
            //除非调用方在调用 getInstance 方法之后又调用了 setSeed 方法；
            //该实现在 windows 上每次生成的 key 都相同，但是在 solaris 或部分 linux 系统上则不同。
//            SecureRandom secureRandom = new SecureRandom(tohash256Deal(key));
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes("UTF-8"));
            keyGenerator.init(256,secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat,ALGORITHM);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding","BC");
            cipher.init(mode,secretKeySpec);
            return cipher;
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 加密
     *
     * @param content
     *          需要加密的内容
     * @param key
     *          key
     * @return
     *          信息加密之后的数据
     */
    private byte[] encrypt(String content,String key){
        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE,key);
            byte[] bytesContent = content.getBytes("UTF-8");
            byte[] cryptograph = cipher.doFinal(bytesContent);
            return org.bouncycastle.util.encoders.Base64.encode(cryptograph);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 解密
     *
     * @param cryptograph
     *          需要解密的byte[]数据
     * @param key
     *          key
     * @return
     *          解密之后的字符串
     */
    private String decrypt(byte[] cryptograph,String key){
        try {
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE,key);
            byte[] result = cipher.doFinal(org.bouncycastle.util.encoders.Base64.decode(cryptograph));
            return new String(result);
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 获取*.keyStore文件中的密钥
     *
     * @return
     *      获取到的密钥
     */
    private String getPrivateKey(){
        try {
            FileInputStream fileInputStream = new FileInputStream("url");
            //*.keyStore文件加密方式是JCEKS
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            //密钥库和别名密码相同
            String password = "44053662";
            String alias = "effort";
            keyStore.load(fileInputStream,password.toCharArray());
            fileInputStream.close();
            return encodeBase64(keyStore.getKey(alias,password.toCharArray()).toString());
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    //字符串加密
    private String encodeBase64(String str) throws UnsupportedEncodingException {
        String bash64Str = new BASE64Encoder().encode(str.getBytes("UTF-8"));
        return bash64Str;
    }
    //字符串解密
    private String decodeBase64(String base64Str) throws IOException {
        byte[] bytes = new BASE64Decoder().decodeBuffer(base64Str);
        String result = new String(bytes,"UTF-8");
        return result;
    }
    /**
     * 转化为16进制数
     *
     * @param bytes
     * @return
     *          16进制数
     */
    private String getHexString(byte[] bytes){
        StringBuilder stringBuilder = new StringBuilder();
        for (int i=0;i<bytes.length;i++){
            String string = Integer.toHexString(bytes[i] & 0XFF).toUpperCase();
            if (string.length() == 2)
                stringBuilder.append(string);
            else
                stringBuilder.append("0").append(string);
        }
        return stringBuilder.toString();
    }
    /**
     * 将16进制的字符串转化为byte数组
     * @param hexStr
     * @return
     */
    private byte[] hexStringToByte(String hexStr){
        if (null == hexStr || "".equals(hexStr))
            return null;
        hexStr = hexStr.toUpperCase();
        int length = hexStr.length() >> 1;
        char[] hexChar = hexStr.toCharArray();
        byte[] bytes = new byte[length];
        for (int i=0;i<length;i++){
            int pos = i << 1;
            bytes[i] = (byte) (charToByte(hexChar[pos]) << 4 | charToByte(hexChar[pos + 1]));
        }
        return bytes;
    }

    private byte charToByte(char c){
        return (byte) "0123456789ABCDEF".indexOf(c);
    }
    /**
     * 提供公开的生成加密文件的方法
     *
     * @param url
     *          需要生成文件的位置
     * @param content
     *          需要加密的数据
     * @throws IOException
     */
    public void createKeyFile(String url,String content) throws IOException {
        try {
            String key = getPrivateKey();
            String encrypyKey = getHexString(encrypt(content,key));
            Writer writer = new FileWriter(url);
            writer.write(encrypyKey);
            writer.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }
    /**
     * 读取加密文件中的信息
     *
     * @param url
     *          读取信息文件的位置
     * @return
     *          解析文件之后的内容
     */
    public String readKeyFile(String url){
        try {
            String key = getPrivateKey();
            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader bufferedReader = new BufferedReader(new FileReader(url));
            String temp = "";
            while ((temp = bufferedReader.readLine())!=null){
                stringBuilder.append(temp);
            }
            temp = stringBuilder.toString();
            byte[] result = hexStringToByte(temp);
            return decrypt(result,key);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {

        String key = "zxyy";
        String password = "0f607264fc6318a92b9e13c65db7cd3c";

        byte[] encryptResult = new AES256ForBC().encrypt(password, key);
        System.out.println("加密："+password);
        System.out.println("密文：" + new AES256ForBC().getHexString(encryptResult));

        String decryptResult = new AES256ForBC().decrypt(encryptResult, key);
        System.out.println("解密：" + decryptResult);
    }
}
