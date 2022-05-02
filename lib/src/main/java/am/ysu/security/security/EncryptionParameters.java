package am.ysu.security.security;

import am.ysu.security.security.util.aes.SecretKeyHelper;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

public class EncryptionParameters {
    public final AlgorithmParameterSpec algorithmParameterSpec;
    public final SecretKey secretKey;

    public EncryptionParameters(AlgorithmParameterSpec algorithmParameterSpec, SecretKey secretKey) {
        this.algorithmParameterSpec = algorithmParameterSpec;
        this.secretKey = secretKey;
    }

    public EncryptionParameters(byte[] algorithmParameterSpec, SecretKey secretKey) {
       this(new IvParameterSpec(algorithmParameterSpec), secretKey);
    }

    public EncryptionParameters(byte[] algorithmParameterSpec, String password) throws InvalidKeySpecException {
        this(new IvParameterSpec(algorithmParameterSpec), SecretKeyHelper.generateSecretKeyPBKDF2(password));
    }

    public EncryptionParameters(IvParameterSpec algorithmParameterSpec, String password) throws InvalidKeySpecException {
        this(algorithmParameterSpec, SecretKeyHelper.generateSecretKeyPBKDF2(password));
    }

    public EncryptionParameters(IvParameterSpec algorithmParameterSpec, String password, byte[] salt) throws  InvalidKeySpecException {
        this(algorithmParameterSpec, SecretKeyHelper.generateSecretKeyPBKDF2(password, salt));
    }

    public EncryptionParameters(byte[] algorithmParameterSpec, String password, String keyAlgorithm) throws InvalidKeySpecException {
        this(new IvParameterSpec(algorithmParameterSpec), SecretKeyHelper.generateSecretKeyPBKDF2(password, keyAlgorithm));
    }

    public EncryptionParameters(byte[] algorithmParameterSpec, String password, byte[] salt, String keyAlgorithm) throws InvalidKeySpecException {
        this(new IvParameterSpec(algorithmParameterSpec), SecretKeyHelper.generateSecretKeyPBKDF2(password, salt, keyAlgorithm));
    }

    public String getKeyEncoded() {
        return new String(secretKey.getEncoded(), StandardCharsets.ISO_8859_1);
    }
}
