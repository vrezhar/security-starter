package am.ysu.security.jwt;

import am.ysu.security.jwt.alg.asymmetric.EcAlgorithm;
import am.ysu.security.jwt.alg.AlgorithmDefinition;
import am.ysu.security.jwt.alg.asymmetric.RsaAlgorithm;
import am.ysu.security.jwt.parsing.error.TokenFormatException;
import am.ysu.security.jwt.parsing.error.TokenStructureException;
import am.ysu.security.jwt.structure.JWTClaims;
import am.ysu.security.jwt.alg.symmetric.HashAlgorithm;
import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.*;

public class JWT {
    private final static String SHA_256_RSA_SIGNING_ALGORITHM = "SHA256withRSA";
    private final static String SHA_256_ECDSA_SIGNING_ALGORITHM = "SHA256withECDSA";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private String headerEncoded;
    private String payloadEncoded;
    private String signature;
    private Map<String, String> header;
    private Map<String, Object> claims;
    private boolean headerOff = false;
    private boolean claimsOff = false;

    public JWT() {
        claims = new LinkedHashMap<>();
        header = new LinkedHashMap<>();
        payloadEncoded = "";
        headerEncoded = "";
    }

    @SuppressWarnings("unchecked")
    public JWT(final String header, final String payload, final String signature) {
        this.headerEncoded = header;
        this.payloadEncoded = payload;
        this.signature = signature;
        try {
            this.claims = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(payload.getBytes(StandardCharsets.UTF_8)),
                    Map.class
            );
            this.header = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(header.getBytes(StandardCharsets.UTF_8)),
                    Map.class
            );
        }
        catch (IOException e) {
            throw new TokenStructureException(e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public JWT(String rawJWT) {
        String[] jwtParts = rawJWT.split("\\.");
        if(jwtParts.length == 3) {
            this.headerEncoded = jwtParts[0];
            this.payloadEncoded = jwtParts[1];
            this.signature = jwtParts[2];
            try{
                this.header = objectMapper.readValue(
                        Base64.getUrlDecoder().decode(jwtParts[0].getBytes(StandardCharsets.UTF_8)),
                        Map.class
                );
                this.claims = objectMapper.readValue(
                        Base64.getUrlDecoder().decode(jwtParts[1].getBytes(StandardCharsets.UTF_8)),
                        Map.class
                );
            }
            catch (IOException e) {
                throw new TokenStructureException(e.getMessage());
            }
        } else if(jwtParts.length == 2) {
            this.headerEncoded = jwtParts[0];
            this.payloadEncoded = jwtParts[1];
            this.signature = null;
            try{
                this.header = objectMapper.readValue(
                        Base64.getUrlDecoder().decode(jwtParts[0].getBytes(StandardCharsets.UTF_8)),
                        Map.class
                );
                if(!header.get(JWTClaims.SIGNATURE_ALGORITHM).equals(JWTClaims.NO_SIGNATURE)){
                    throw new IllegalArgumentException("Token signature is missing, but a signature algorithm is specified in the header");
                }
                this.claims = objectMapper.readValue(
                        Base64.getUrlDecoder().decode(jwtParts[1].getBytes(StandardCharsets.UTF_8)),
                        Map.class
                );
            }
            catch (IOException e) {
                throw new TokenStructureException(e.getMessage());
            }
        } else {
            throw new TokenFormatException("Invalid JWT, cannot identify the header, payload and signature");
        }
    }

    public JWT(final Map<String, String> headerMap, final Map<String, Object> claims, final RSAPrivateKey privateKey) {
        this.claims = claims;
        this.header = headerMap;
        try {
            this.headerEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(headerMap));
            this.payloadEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(claims));
            final Signature sig = Signature.getInstance(RsaAlgorithm.RS256.getJavaAlgorithmName());
            sig.initSign(privateKey);
            sig.update((headerEncoded + "." + payloadEncoded).getBytes(StandardCharsets.UTF_8));
            this.signature = getUrlEncoder().encodeToString(sig.sign());
        } catch (Exception e){
            throw new RuntimeException("Unable to initialize JWT due to unexpected exception, message is " + e.getMessage(), e);
        }
    }

    public JWT(final Map<String, String> headerMap, final Map<String, Object> claims, final ECPrivateKey privateKey) {
        this.claims = claims;
        this.header = headerMap;
        try {
            this.headerEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(headerMap));
            this.payloadEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(claims));
            final Signature sig = Signature.getInstance(EcAlgorithm.ES256.getJavaAlgorithmName());
            sig.initSign(privateKey);
            sig.update((headerEncoded + "." + payloadEncoded).getBytes(StandardCharsets.UTF_8));
            this.signature = getUrlEncoder().encodeToString(sig.sign());
        } catch (Exception e){
            throw new RuntimeException("Unable to initialize JWT due to unexpected exception, message is " + e.getMessage(), e);
        }
    }

    public JWT(final Map<String, String> headerMap, final Map<String, Object> claims) {
        this.claims = claims;
        this.header = headerMap;
        try {
            this.headerEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(headerMap));
            this.payloadEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(claims));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Unable to initialize JWT due to unexpected exception, message is " + e.getMessage(), e);
        }
        this.signature = null;
    }

    public String getHeaderEncoded() {
        if(headerOff){
            try {
                this.headerEncoded =  getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(this.header));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Unable to serialize JWT header due to unexpected exception, message is " + e.getMessage(), e);
            }
            this.headerOff = false;
        }
        return headerEncoded;
    }

    public String getPayloadEncoded() {
        if(claimsOff){
            try {
                this.payloadEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(this.claims));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Unable to serialize JWT claims due to unexpected exception, message is " + e.getMessage(), e);
            }
            this.claimsOff = false;
        }
        return payloadEncoded;
    }


    public String getSignatureAsString() {
        return signature != null ? new String(Base64.getUrlDecoder().decode(signature.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8) : null;
    }

    public String getSignatureEncoded() {
        return this.signature;
    }

    public String getJSONWebKeyURL() {
        return header.get(JWTClaims.JSON_WEB_KEY_URL);
    }

    public byte[] getSignature() {
        return signature != null ? Base64.getUrlDecoder().decode(signature.getBytes(StandardCharsets.UTF_8)) : null;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public Object getClaim(String key) {
        return claims.get(key);
    }

    public void setClaim(String name, Object value) {
        if(this.signature != null){
            throw new IllegalStateException("Claims of a signed JWT must not be altered");
        }
        claims.put(name, value);
        this.claimsOff = true;
    }

    public void setClaims(Map<String, Object> claims) {
        if(this.signature != null){
            throw new IllegalStateException("Claims of a signed JWT must not be altered");
        }
        this.claims = claims;
        try {
            this.payloadEncoded = Base64.getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(claims));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Unexpected fatal error during serialization of claims: " + e.getMessage(), e);
        }
        this.claimsOff = false;
    }

    public void sign(PrivateKey privateKey, AlgorithmDefinition algorithmDefinition) throws SignatureException {
        initHeader(algorithmDefinition);
        this.signature = getUrlEncoder().encodeToString(doSign(privateKey, algorithmDefinition));
    }

    public void sign(RSAPrivateKey key) {
        initHeader(RsaAlgorithm.RS256);
        final Signature sig;
        try {
            sig = Signature.getInstance(SHA_256_RSA_SIGNING_ALGORITHM);
            sig.initSign(key);
            sig.update(getHeaderAndPayloadBytes());
            this.signature = getUrlEncoder().encodeToString(sig.sign());
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Unable to sign JWT due to unexpected exception, message is " + e.getMessage(), e);
        }
    }

    public void sign(ECPrivateKey key) {
        initHeader(EcAlgorithm.ES256);
        try {
            final Signature sig = Signature.getInstance(SHA_256_ECDSA_SIGNING_ALGORITHM);
            sig.initSign(key);
            sig.update(getHeaderAndPayloadBytes());
            this.signature = getUrlEncoder().encodeToString(sig.sign());
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException("Unable to sign JWT due to unexpected exception, message is " + e.getMessage(), e);
        }
    }

    public void sign(String key, HashAlgorithm hashAlgorithm) throws InvalidKeyException {
        initHeader(hashAlgorithm);
        try {
            this.signature = Base64.getUrlEncoder().withoutPadding().encodeToString(HashingAndEncryptionHelper.hmac(key, hashAlgorithm.getJavaAlgorithmName(), getHeaderAndPayloadBytes()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected NoSuchAlgorithmException, cannot create Mac " + hashAlgorithm.getJavaAlgorithmName(), e);
        }
    }

    @SuppressWarnings("unchecked")
    public void setHeader(String header) {
        if(this.signature != null){
            throw new IllegalStateException("Header of a signed JWT must not be altered");
        }
        this.headerEncoded = header;
        try {
            this.header = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(header.getBytes(StandardCharsets.UTF_8)),
                    Map.class
            );
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        this.headerOff = false;
    }

    public Map<String, String> getHeader() {
        return header;
    }

    public String getHeaderClaim(String key) {
        return header.get(key);
    }

    @SuppressWarnings("unchecked")
    public void setPayload(String payload) {
        if(this.signature != null){
            throw new IllegalStateException("Payload of a signed JWT must not be altered");
        }
        this.payloadEncoded = payload;
        try {
            this.claims = objectMapper.readValue(Base64.getUrlDecoder().decode(payloadEncoded.getBytes(StandardCharsets.UTF_8)), Map.class);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
        this.claimsOff = false;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getJWTEncoded() {
        return getHeaderEncoded() + "." + getPayloadEncoded() + (signature != null ? "." + signature : "");
    }

    public byte[] getHeaderAndPayloadBytes() {
        return (getHeaderEncoded() + "." + getPayloadEncoded()).getBytes(StandardCharsets.UTF_8);
    }

    public String getIssuer() {
        final Object issuer = claims.get(JWTClaims.ISSUER);
        return issuer != null ? issuer.toString() : null;
    }

    public String getSubject() {
        final Object subject = claims.get(JWTClaims.SUBJECT);
        return subject != null ? subject.toString() : null;
    }

    public Date getExpirationDate() {
        Object expDate = claims.get(JWTClaims.EXPIRATION_DATE);
        return asDate(expDate, JWTClaims.EXPIRATION_DATE);
    }

    public Date getIssuedDate() {
        Object expDate = claims.get(JWTClaims.ISSUING_DATE);
        return asDate(expDate, JWTClaims.ISSUING_DATE);
    }

    public Date getNotBeforeDate() {
        Object nbeDate = claims.get(JWTClaims.NOT_BEFORE_DATE);
        return asDate(nbeDate, JWTClaims.NOT_BEFORE_DATE);
    }

    @SuppressWarnings("unchecked")
    public List<String> getAudience() {
        Object aud = claims.get(JWTClaims.AUDIENCE);
        if(aud != null){
            if(aud instanceof List){
                return (List<String>)aud;
            } else {
                return Arrays.asList(aud.toString().trim().split(","));
            }
        }
        return new ArrayList<>();
    }

    public String getNonce() {
        Object nonce = claims.get(JWTClaims.NONCE);
        return nonce != null ? (String)nonce : null;
    }

    public String getTokenId() {
        return header.getOrDefault(JWTClaims.TOKEN_ID, (String)claims.getOrDefault(JWTClaims.TOKEN_ID, ""));
    }

    public String getSignatureAlgorithm() {
        return header.get(JWTClaims.SIGNATURE_ALGORITHM);
    }

    public String getPublicKeyId() {
        return header.get(JWTClaims.PUBLIC_KEY_ID);
    }

    public boolean isSigned() {
        return signature != null;
    }

    public String getAccessTokenHash() {
        final Object accessTokenHash = claims.get(JWTClaims.ACCESS_TOKEN_HASH);
        return accessTokenHash != null ? accessTokenHash.toString() : null;
    }

    public String getAuthorizationCodeHash() {
        final Object authCodeHash = claims.get(JWTClaims.AUTHORIZATION_CODE_HASH);
        return authCodeHash != null ? authCodeHash.toString() : null;
    }

    public Date getAuthenticationDate() {
        Object authnDate = claims.get(JWTClaims.AUTHENTICATION_TIME);
        return asDate(authnDate, JWTClaims.AUTHENTICATION_TIME);
    }

    private void initHeader(AlgorithmDefinition algorithmDefinition) {
        String algorithm = this.header.get(JWTClaims.SIGNATURE_ALGORITHM);
        final String algorithmName = algorithmDefinition.getJwtAlgorithmName();
        if(algorithm == null) {
            this.header.put(JWTClaims.SIGNATURE_ALGORITHM, algorithmName);
            try {
                this.headerEncoded = getUrlEncoder().encodeToString(objectMapper.writeValueAsString(this.header).getBytes(StandardCharsets.UTF_8));
            } catch (JsonProcessingException e) {
                throw new RuntimeException("Unable to serialize JWT header due to unexpected exception, message is " + e.getMessage(), e);
            }
            this.headerOff = false;
        } else {
            if(!algorithm.equals(algorithmName)){
                throw new UnsupportedOperationException("Algorithm name mismatch; " + algorithm + " in header, " + algorithmName + " provided");
            }
        }
    }

    private byte[] doSign(PrivateKey privateKey, AlgorithmDefinition algorithmDefinition) throws SignatureException {
        final Signature sig;
        try {
            sig = Signature.getInstance(algorithmDefinition.getJavaAlgorithmName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to instantiate signature " + algorithmDefinition.getJavaAlgorithmName(), e);
        }
        try {
            sig.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Provided key does not match with the signature algorithm", e);
        }
        final var paramSpec = algorithmDefinition.getParameter();
        if(paramSpec != null) {
            try {
                sig.setParameter(paramSpec);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Unable to initialize signature algorithm parameter spec " + paramSpec, e);
            }
        }
        sig.update(getHeaderAndPayloadBytes());
        return sig.sign();
    }

    public static JWT fromAuthorizationHeader(String authHeader) {
        return new JWT(authHeader.replace("Bearer ", ""));
    }

    private static Base64.Encoder getUrlEncoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }

    private static Date asDate(Object date, String claim) {
        try{
            if(date != null){
                if(date instanceof Date){
                    return (Date)date;
                }
                if(date instanceof Number){
                    return Date.from(Instant.ofEpochSecond(((Number)date).longValue()));
                }
                else {
                    return Date.from(Instant.ofEpochSecond(Long.parseLong(date.toString())));
                }
            }
        }
        catch (Exception e){
            throw new IllegalArgumentException("Presented claim " + claim + " does not have a value corresponding to a known date format(claim value is " + date + ")");
        }
        return null;
    }
}
