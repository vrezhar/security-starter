package am.ysu.security.jwk;

import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonSetter;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public abstract class BaseJWK implements JWK {
    protected String keyType;
    protected String algorithm;
    protected String keyId;
    protected String usage;

    public BaseJWK(){ }

    protected BaseJWK(String keyType, String algorithm, String keyId, String usage) {
        this.keyType = keyType;
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.usage = usage;
    }

    @Override
    @JsonGetter(JWKFields.KEY_TYPE)
    public String getKeyType() {
        return keyType;
    }

    @JsonSetter(JWKFields.KEY_TYPE)
    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    @Override
    @JsonGetter(JWKFields.ALGORITHM)
    public String getAlgorithm() {
        return algorithm;
    }

    @JsonSetter(JWKFields.ALGORITHM)
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    @JsonGetter(JWKFields.KEY_ID)
    public String getKeyId() {
        return keyId;
    }

    @JsonSetter(JWKFields.KEY_ID)
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    @Override
    @JsonGetter(JWKFields.KEY_USAGE)
    public String getUsage() {
        return usage;
    }

    @JsonSetter(JWKFields.KEY_USAGE)
    public void setUsage(String usage) {
        this.usage = usage;
    }

    protected static String encodeBigIntegerUnsigned(BigInteger integer) {
        byte[] dataToEncode = integer.toByteArray();
        return Base64.getUrlEncoder().encodeToString(new BigInteger(1, dataToEncode).toByteArray());
    }

    protected static BigInteger decodeBigIntegerUnsigned(String base64UrlUIntEncodedValue) {
        BigInteger decoded = new BigInteger(Base64.getUrlDecoder().decode(base64UrlUIntEncodedValue));
        if(decoded.compareTo(BigInteger.ZERO) < 0){
            return decoded.add(BigInteger.ONE.shiftLeft(decoded.toByteArray().length * 8));
        }
        return decoded;
    }

    protected static String calculateFingerPrint(PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(publicKey.getEncoded());
        return Base64.getEncoder().encodeToString(messageDigest.digest());
    }

    public static String calculateFingerPrintHex(PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(publicKey.getEncoded());
        byte[] fingerprintDigest = messageDigest.digest();
        return HashingAndEncryptionHelper.bytesToHex(fingerprintDigest);
    }
}
