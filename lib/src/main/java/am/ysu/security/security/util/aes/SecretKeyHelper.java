package am.ysu.security.security.util.aes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SecretKeyHelper
{
    public static final String DEFAULT_KEY_ALGORITHM = "AES";
    public static final String HMAC_KEY_ALGORITHM = "HmacSHA256";

    private static SecretKeyFactory getSecretKeyFactory() {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Secret key factory unavailable, something is wrong with the JRE", e);
        }
    }

    private SecretKeyHelper() { }

    public static SecretKey generateAesSecretKey(String fromSecret) {
        return new SecretKeySpec(fromSecret.getBytes(StandardCharsets.ISO_8859_1), DEFAULT_KEY_ALGORITHM);
    }

    public static SecretKey generateHmacSecretKey(String key){
        return new SecretKeySpec(key.getBytes(StandardCharsets.ISO_8859_1), HMAC_KEY_ALGORITHM);
    }

    public static SecretKey generateSecretKey(byte[] fromSecret, String algorithm) {
        return new SecretKeySpec(fromSecret, algorithm);
    }

    public static SecretKey generateSecretKey(String fromSecret, String algorithm) {
        return new SecretKeySpec(fromSecret.getBytes(StandardCharsets.ISO_8859_1), algorithm);
    }

    public static SecretKey generateRandomSecretKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(DEFAULT_KEY_ALGORITHM);
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateRandomSecretKey() throws NoSuchAlgorithmException {
        return generateRandomSecretKey(128);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, byte[] salt, int iterations, int keyLength, String keyAlgorithm) throws InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKey secretKey = getSecretKeyFactory().generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), keyAlgorithm);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, byte[] salt, int iterations) throws InvalidKeySpecException {
        return generateSecretKeyPBKDF2(password, salt, iterations, 128, DEFAULT_KEY_ALGORITHM);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, byte[] salt, int iterations, int keyLength) throws InvalidKeySpecException {
        return generateSecretKeyPBKDF2(password, salt, iterations, keyLength, DEFAULT_KEY_ALGORITHM);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, byte[] salt) throws InvalidKeySpecException {
        return generateSecretKeyPBKDF2(password, salt, 1024, 128, DEFAULT_KEY_ALGORITHM);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, byte[] salt, String keyAlgorithm) throws InvalidKeySpecException {
        return generateSecretKeyPBKDF2(password, salt, 1024, 128, keyAlgorithm);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password) throws InvalidKeySpecException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return generateSecretKeyPBKDF2(password, salt, DEFAULT_KEY_ALGORITHM);
    }

    public static SecretKeySpec generateSecretKeyPBKDF2(String password, String algorithm) throws InvalidKeySpecException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return generateSecretKeyPBKDF2(password, salt, algorithm);
    }

    public static IvParameterSpec generateIVParameterSpec(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static IvParameterSpec generateIVParameterSpec() {
        return generateIVParameterSpec(16);
    }

    public static GCMParameterSpec generateGCMParameterSpec(int tagLength, int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return new GCMParameterSpec(tagLength, iv);
    }

    public static GCMParameterSpec generateGCMParameterSpec(int size) {
        return generateGCMParameterSpec(128, size);
    }
}
