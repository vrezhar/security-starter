package am.ysu.security.security.util.key;

import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.Base64;

public class KeyUtils {
    private static final String PUBLIC_KEY_START = "-----BEGIN PUBLIC KEY-----";
    private static final String PRIVATE_KEY_START = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    public static final String DEFAULT_HASHING_ALGORITHM = "SHA-256";
    public static final String EDWARDS_CURVE_25519 = "Ed25519";

    private KeyUtils(){ }

    public static KeyFactory getRsaKeyFactory(){
        try {
            return KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to load RSA key factory, something is wrong with the JDK", e);
        }
    }

    public static KeyFactory getEccKeyFactory(){
        try {
            return KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to load EC key factory, something is wrong with the JDK", e);
        }
    }

    public static KeyFactory getEdECKeyFactory() {
        try {
            return KeyFactory.getInstance(EDWARDS_CURVE_25519);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to load EC key factory, something is wrong with the JDK", e);
        }
    }

    public static RSAPublicKey getRsaPublicKey(final String publicKey) throws InvalidKeySpecException {
        return (RSAPublicKey) doGetPublicKey(getRsaKeyFactory(), publicKey);
    }

    public static RSAPrivateKey getRsaPrivateKey(final String privateKey) throws InvalidKeySpecException {
        return (RSAPrivateKey) doGetPrivateKey(getRsaKeyFactory(), privateKey);
    }

    public static ECPublicKey getEcPublicKey(String publicKey) throws InvalidKeySpecException {
        return (ECPublicKey) doGetPublicKey(getEccKeyFactory(), publicKey);
    }

    public static ECPrivateKey getEcPrivateKey(final String privateKey) throws InvalidKeySpecException {
        return (ECPrivateKey) doGetPrivateKey(getEccKeyFactory(), privateKey);
    }

    public static EdECPrivateKey getEdECPrivateKey(final String privateKey) throws InvalidKeySpecException {
        return (EdECPrivateKey) doGetPrivateKey(getEdECKeyFactory(), privateKey);
    }

    public static EdECPublicKey getEdECPublicKey(String publicKey) throws InvalidKeySpecException {
        return (EdECPublicKey) doGetPublicKey(getEdECKeyFactory(), publicKey);
    }

    public static EdECPrivateKey getEdECPrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException {
        final var keyFactory = getEdECKeyFactory();
        final var privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKeyBytes);
        return (EdECPrivateKey)keyFactory.generatePrivate(privateKeySpec);
    }

    public static EdECPublicKey getEdECPublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException {
        final var keyFactory = getEdECKeyFactory();
        final var paramSpec = new NamedParameterSpec(EDWARDS_CURVE_25519);
        final boolean xOdd = (publicKeyBytes[publicKeyBytes.length - 1] & 255) >> 7 == 1;
        //key encoding is little endian, need to make it big endian to instantiate in a big integer
        final byte[] bytesReversed = new byte[publicKeyBytes.length];
        for(int i = 0; i < publicKeyBytes.length; ++i) {
            bytesReversed[i] = publicKeyBytes[publicKeyBytes.length - 1 - i];
        }
        bytesReversed[0] &= 127;
        final var ecPoint = new EdECPoint(xOdd, new BigInteger(1, bytesReversed));
        final var publicKeySpec = new EdECPublicKeySpec(paramSpec, ecPoint);
        return (EdECPublicKey)keyFactory.generatePublic(publicKeySpec);
    }

    public static KeyPair generateEdECKeyPair() {
        try {
            return KeyPairGenerator.getInstance(EDWARDS_CURVE_25519).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to instantiate Ed25519 keypair generator, check the JRE version", e);
        }
    }

    public static KeyPair generateEdECKeyPair(int keySize, SecureRandom secureRandom) {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EDWARDS_CURVE_25519);
            keyPairGenerator.initialize(NamedParameterSpec.ED25519);
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Unable to instantiate Ed25519 keypair generator, check the JRE version", e);
        }
    }

    public static KeyPair generateEdECKeyPair(SecureRandom secureRandom) {
        return generateEdECKeyPair(255, secureRandom);
    }

    private static PublicKey doGetPublicKey(KeyFactory keyFactory, String publicKey) throws InvalidKeySpecException {
        return keyFactory.generatePublic(
                new X509EncodedKeySpec(
                        Base64
                                .getDecoder()
                                .decode(
                                        publicKey
                                                .replace(PUBLIC_KEY_START, "")
                                                .replaceAll(System.lineSeparator(), "")
                                                .replace(PUBLIC_KEY_END, "").getBytes(StandardCharsets.UTF_8)
                                )
                )
        );
    }

    private static PrivateKey doGetPrivateKey(KeyFactory keyFactory, String privateKey) throws InvalidKeySpecException {
        return keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(
                        Base64
                                .getDecoder()
                                .decode(
                                        privateKey
                                                .replace(PRIVATE_KEY_START, "")
                                                .replaceAll(System.lineSeparator(), "")
                                                .replace(PRIVATE_KEY_END, "")
                                )
                )
        );
    }

    public static String calculateFingerPrint(PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(publicKey.getEncoded());
        return Base64.getEncoder().encodeToString(messageDigest.digest());
    }

    public static String calculateFingerPrint(PublicKey publicKey) {
        try {
            return calculateFingerPrint(publicKey, DEFAULT_HASHING_ALGORITHM);
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException(DEFAULT_HASHING_ALGORITHM + " algorithm not supported", nse);
        }
    }

    public static String calculateFingerPrintHex(PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(publicKey.getEncoded());
        byte[] fingerprintDigest = messageDigest.digest();
        return HashingAndEncryptionHelper.bytesToHex(fingerprintDigest).substring(0, 16).toLowerCase();
    }

    public static String calculateFingerPrintHex(PublicKey publicKey) {
        try {
            return calculateFingerPrintHex(publicKey, DEFAULT_HASHING_ALGORITHM);
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException(DEFAULT_HASHING_ALGORITHM + " algorithm not supported", nse);
        }
    }
}
