package am.ysu.security.jwk.ec;

import am.ysu.security.jwk.BaseJWK;
import am.ysu.security.jwk.JWKFields;
import am.ysu.security.security.util.key.KeyUtils;
import am.ysu.security.security.util.key.NistEcCurve;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

public class EcJWK extends BaseJWK {
    private String curve;
    private BigInteger ecPointX;
    private BigInteger ecPointY;

    public EcJWK(){ }

    @JsonCreator
    public EcJWK(
            @JsonProperty(JWKFields.KEY_TYPE) String keyType,
            @JsonProperty(JWKFields.ALGORITHM) String algorithm,
            @JsonProperty(JWKFields.KEY_ID) String keyId,
            @JsonProperty(JWKFields.KEY_USAGE) String usage,
            @JsonProperty(JWKFields.ELLIPTIC_CURVE_TYPE) String curve,
            @JsonProperty(JWKFields.EC_POINT_X) String ecPointX,
            @JsonProperty(JWKFields.EC_POINT_Y) String ecPointY
    )
    {
        super(keyType, algorithm, keyId, usage);
        this.curve = curve;
        this.ecPointX = decodeBigIntegerUnsigned(ecPointX);
        this.ecPointY = decodeBigIntegerUnsigned(ecPointY);
    }

    @JsonGetter(JWKFields.ELLIPTIC_CURVE_TYPE)
    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }

    @JsonIgnore
    public BigInteger getEcPointX() {
        return ecPointX;
    }

    @JsonIgnore
    public void setEcPointX(BigInteger ecPointX) {
        this.ecPointX = ecPointX;
    }

    @JsonIgnore
    public BigInteger getEcPointY() {
        return ecPointY;
    }

    @JsonIgnore
    public void setEcPointY(BigInteger ecPointY) {
        this.ecPointY = ecPointY;
    }

    @JsonGetter(JWKFields.EC_POINT_X)
    public String getEcPointXEncoded() {
        if(ecPointX == null){
            return "infinity";
        }
        return encodeBigIntegerUnsigned(ecPointX);
    }

    @JsonGetter(JWKFields.EC_POINT_Y)
    public String getEcPointYEncoded() {
        if(ecPointY == null){
            return "infinity";
        }
        return encodeBigIntegerUnsigned(ecPointY);
    }

    public static EcJWK from(String jwkJSON) throws JsonProcessingException {
        return new ObjectMapper().readValue(jwkJSON, EcJWK.class);
    }

    public ECPublicKey toPublicKey() throws InvalidKeySpecException {
        final var keyFactory = KeyUtils.getEccKeyFactory();
        final var w = new ECPoint(ecPointX, ecPointY);
        return (ECPublicKey)keyFactory.generatePublic(new ECPublicKeySpec(w, NistEcCurve.P256.getParameterSpec()));
    }

    public static EcJWK from(ECPublicKey publicKey, String fingerprintAlgorithm) throws NoSuchAlgorithmException {
        ECPoint point = publicKey.getW();
        EcJWK ecJWK = new EcJWK();
        ecJWK.setKeyType(JWKFields.ELLIPTIC_CURVE_KEY_TYPE);
        ecJWK.setUsage(JWKFields.USAGE_FOR_SIGNING);
        ecJWK.setAlgorithm(JWKFields.DEFAULT_ELLIPTIC_CURVE_ALGORITHM);
        ecJWK.setCurve(JWKFields.DEFAULT_ELLIPTIC_CURVE_TYPE);
        ecJWK.setEcPointX(point.getAffineX());
        ecJWK.setEcPointY(point.getAffineY());
        ecJWK.setKeyId(calculateFingerPrintHex(publicKey, fingerprintAlgorithm));
        return ecJWK;
    }

    public static EcJWK from(ECPublicKey publicKey) {
        try {
            return from(publicKey, "SHA-256");
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException("Unable to calculate public key fingerprint using SHA-256", nse);
        }
    }
}
