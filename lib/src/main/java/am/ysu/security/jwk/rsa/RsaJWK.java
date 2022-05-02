package am.ysu.security.jwk.rsa;

import am.ysu.security.jwk.BaseJWK;
import am.ysu.security.jwk.JWKFields;
import am.ysu.security.security.util.key.KeyUtils;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RsaJWK extends BaseJWK {
    private BigInteger publicExponent;
    private BigInteger modulus;

    @JsonGetter(JWKFields.PUBLIC_EXPONENT)
    public String getPublicExponentEncoded() {
        return encodeBigIntegerUnsigned(publicExponent);
    }

    @JsonGetter(JWKFields.MODULUS)
    public String getModulusEncoded() {
        return encodeBigIntegerUnsigned(modulus);
    }

    @JsonSetter(JWKFields.PUBLIC_EXPONENT)
    public void setPublicExponentFromEncodedString(String publicExponentEncoded) {
        publicExponent = decodeBigIntegerUnsigned(publicExponentEncoded);
    }

    @JsonSetter(JWKFields.MODULUS)
    public void setModulusFromEncodedString(String modulusExponentEncoded) {
        modulus = decodeBigIntegerUnsigned(modulusExponentEncoded);
    }

    @JsonIgnore
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @JsonIgnore
    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    @JsonIgnore
    public BigInteger getModulus() {
        return modulus;
    }

    @JsonIgnore
    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public PublicKey toPublicKey() throws InvalidKeySpecException {
        KeyFactory factory = KeyUtils.getRsaKeyFactory();
        KeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        return factory.generatePublic(keySpec);
    }

    public String serialize() throws JsonProcessingException {
        return new ObjectMapper().writeValueAsString(this);
    }

    public static RsaJWK from(String jwkJSON) throws JsonProcessingException {
        return new ObjectMapper().readValue(jwkJSON, RsaJWK.class);
    }

    public static RsaJWK from(RSAPublicKey publicKey, String fingerprintAlgorithm) throws NoSuchAlgorithmException {
        RsaJWK rsaJwk = new RsaJWK();
        rsaJwk.setUsage(JWKFields.USAGE_FOR_SIGNING);
        rsaJwk.setKeyType(JWKFields.RSA_KEY_TYPE);
        rsaJwk.setAlgorithm(JWKFields.DEFAULT_RSA_ALGORITHM);
        rsaJwk.setPublicExponent(publicKey.getPublicExponent());
        rsaJwk.setModulus(publicKey.getModulus());
        rsaJwk.setKeyId(calculateFingerPrintHex(publicKey, fingerprintAlgorithm));
        return rsaJwk;
    }

    public static RsaJWK from(RSAPublicKey publicKey) {
        try {
            return from(publicKey, "SHA-256");
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException("Unable to calculate public key fingerprint using SHA-256", nse);
        }
    }

    public static String calculateFingerPrintHex(RSAPublicKey publicKey) {
        try {
            return calculateFingerPrintHex(publicKey, "SHA-256");
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException("Unable to calculate public key fingerprint using SHA-256", nse);
        }
    }
}
