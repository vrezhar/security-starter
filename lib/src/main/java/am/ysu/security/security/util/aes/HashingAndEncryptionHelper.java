package am.ysu.security.security.util.aes;

import am.ysu.security.security.EncryptionContext;
import am.ysu.security.security.EncryptionParameters;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class HashingAndEncryptionHelper {
    private static final char[] HEX_CODE = "0123456789ABCDEF".toCharArray();

    public static final String DEFAULT_ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    public static final String HMAC_SHA_256 = "HmacSHA256";

    private HashingAndEncryptionHelper() { }

    public static Mac getMac(String algorithm) throws NoSuchAlgorithmException {
        return Mac.getInstance(algorithm);
    }

    public static Mac getMac() {
        try {
            return Mac.getInstance(HMAC_SHA_256);
        }
        catch (Exception e){
            throw new RuntimeException("HMAC with SHA-256 Mac is not available, something is wrong with the JRE", e);
        }
    }

    public static SecretKeyFactory getPBKDF2SecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Secret key factory unavailable, something is wrong with the JRE", e);
        }
    }

    public static byte[] hmac(String key, byte[] data) throws InvalidKeyException {
        Mac hmac = getMac();
        hmac.init(SecretKeyHelper.generateHmacSecretKey(key));
        return hmac.doFinal(data);
    }

    public static byte[] hmac(String key, String hashAlgorithm, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        Mac hmac = getMac(hashAlgorithm);
        hmac.init(SecretKeyHelper.generateHmacSecretKey(key));
        return hmac.doFinal(data);
    }

    public static String hmacAndHex(String key, byte[] data) throws InvalidKeyException {
        return bytesToHex(hmac(key, data));
    }

    public static String bytesToHex(byte[] data) {
        StringBuilder hex = new StringBuilder(data.length * 2);
        for (byte b : data) {
            hex.append(HEX_CODE[(b >> 4) & 0xF]);
            hex.append(HEX_CODE[(b & 0xF)]);
        }
        return hex.toString();
    }

    public static byte[] digest(byte[] dataToHash, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(dataToHash);
        return messageDigest.digest();
    }

    public static byte[] digestSHA256(byte[] dataToHash) {
        try {
            return digest(dataToHash, "SHA-256");
        }
        catch (NoSuchAlgorithmException ne){
            throw new RuntimeException("SHA-256 algorithm not found, something is wrong with the JDK", ne);
        }
    }

    public static String digestAndHex(byte[] dataToHash, String algorithm) throws NoSuchAlgorithmException {
        return bytesToHex(digest(dataToHash, algorithm));
    }

    public static String digestSHA256AndHex(byte[] dataToHash) {
        return bytesToHex(digestSHA256(dataToHash));
    }

    public static String digestAndBase64Encode(byte[] dataToHash, String algorithm) throws NoSuchAlgorithmException {
        return Base64.getEncoder().encodeToString(digest(dataToHash, algorithm));
    }

    public static String digestSHA256AndBase64Encode(byte[] dataToHash) {
        return Base64.getEncoder().encodeToString(digestSHA256(dataToHash));
    }


    public static EncryptionContext encrypt(byte[] input, SecretKey key, IvParameterSpec ivParameter, String algorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameter);
        byte[] cipherText = cipher.doFinal(input);
        return new EncryptionContext(Base64.getEncoder().encodeToString(cipherText), ivParameter, key);
    }

    public static EncryptionContext encrypt(byte[] input, SecretKey key) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input, key, SecretKeyHelper.generateIVParameterSpec(), DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public static EncryptionContext encrypt(byte[] input, SecretKey key, String algorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input, key, SecretKeyHelper.generateIVParameterSpec(), algorithm);
    }


    public static EncryptionContext encrypt(byte[] input, SecretKey key, IvParameterSpec parameter) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input, key, parameter, DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public static EncryptionContext encrypt(String input, SecretKey key, IvParameterSpec ivParameter, String algorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input.getBytes(StandardCharsets.ISO_8859_1), key, ivParameter, algorithm);
    }

    public static EncryptionContext encrypt(String input, SecretKey key, IvParameterSpec ivParameter) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input.getBytes(StandardCharsets.ISO_8859_1), key, ivParameter, DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public static EncryptionContext encrypt(String input, SecretKey key) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input.getBytes(StandardCharsets.ISO_8859_1), key, SecretKeyHelper.generateIVParameterSpec(), DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public static EncryptionContext encrypt(String input, SecretKey key, String algorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input.getBytes(StandardCharsets.ISO_8859_1), key, SecretKeyHelper.generateIVParameterSpec(), algorithm);
    }


    public static EncryptionContext encryptUsingPassword(String input, String password, byte[] salt) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt));
    }

    public static EncryptionContext encryptUsingPassword(byte[] input, String password, byte[] salt) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt));
    }

    public static EncryptionContext encryptUsingPassword(byte[] input, String password, byte[] salt, String algorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt), algorithm);
    }

    public static EncryptionContext encryptUsingPassword(String input, String password, byte[] salt, IvParameterSpec parameterSpec) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt), parameterSpec);
    }

    public static EncryptionContext encryptUsingPassword(String input, String password, byte[] salt, IvParameterSpec parameterSpec, String keyAlgorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt), parameterSpec, keyAlgorithm);
    }

    public static EncryptionContext encryptUsingPassword(String input, String password, byte[] salt, String keyAlgorithm) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return encrypt(input, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt, keyAlgorithm));
    }

    public static EncryptionContext encryptWithRandomKey(String input) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input, SecretKeyHelper.generateRandomSecretKey());
    }

    public static EncryptionContext encryptWithRandomKey(String input, int keyLength) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return encrypt(input, SecretKeyHelper.generateRandomSecretKey(keyLength));
    }

    public static String decrypt(String encrypted, SecretKey key, AlgorithmParameterSpec parameter, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, parameter);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decrypted, StandardCharsets.ISO_8859_1);
    }

    public static String decrypt(String encrypted, SecretKey key, IvParameterSpec ivParameter)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
       return decrypt(encrypted, key, ivParameter, DEFAULT_ENCRYPTION_ALGORITHM);
    }

    public static String decrypt(String encrypted, EncryptionParameters parameters, String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return decrypt(encrypted, parameters.secretKey, parameters.algorithmParameterSpec, algorithm);
    }

    public static String decrypt(String encrypted, EncryptionParameters parameters)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        return decrypt(encrypted, parameters.secretKey, parameters.algorithmParameterSpec, DEFAULT_ENCRYPTION_ALGORITHM);
    }

}
