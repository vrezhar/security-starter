package am.ysu.security.paseto.utils.protocol;

import am.ysu.security.paseto.utils.Helper;
import am.ysu.security.paseto.utils.error.EncryptionException;
import am.ysu.security.paseto.ProtocolSpecImplementor;
import am.ysu.security.paseto.utils.Constants;
import am.ysu.security.paseto.utils.error.AuthenticationException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;


public class V1ProtocolImplementor implements ProtocolSpecImplementor {
    private static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static String SECURE_RANDOM_PROVIDER = "SUN";

    private static final V1ProtocolImplementor INSTANCE = new V1ProtocolImplementor();

    public static V1ProtocolImplementor getInstance() {
        return INSTANCE;
    }

    public static void setSecureRandomAlgorithm(String algorithm) {
        SECURE_RANDOM_ALGORITHM = algorithm;
    }

    public static void setSecureRandomProvider(String provider) {
        SECURE_RANDOM_PROVIDER = provider;
    }

    private V1ProtocolImplementor() { }

    /**
     * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1decrypt">Paseto v1.Decrypt</a>
     */
    @Override
    public String decrypt(byte[] key, String token) {
        if(!token.startsWith(Constants.V1.LOCAL_HEADER)) {
            throw new IllegalArgumentException("Passed token " + token + " is not a valid PASETO v1 local token");
        }
        final String[] parts = token.split("\\.");
        //0 is v1, 1 is local, 2 is message and three might be the footer if the length of parts is 4
        final String m = parts[2];
        final byte[] f;
        if(parts.length == 4) {
            f = B64_DECODER.decode(parts[3]);
        } else {
            f = "".getBytes(StandardCharsets.UTF_8);
        }
        final byte[] payload = B64_DECODER.decode(m);
        if(payload.length < 80) {
            throw new IllegalArgumentException("Payload " + new String(payload, StandardCharsets.UTF_8) + " too small too bee encrypted by v1 encryption method");
        }
        //leftmost 32 bytes of the payload
        final byte[] n = Arrays.copyOf(payload, 32);
        final byte[] hkdfSalt = Arrays.copyOf(n, 16);
        //rightmost 48 bytes of the payload
        final byte[] t = Arrays.copyOfRange(payload, payload.length - 48, payload.length);
        //inbetween the leftmost 32 bytes and rightmost 48 bytes.
        final byte[] c = Arrays.copyOfRange(payload, 32, payload.length - 48);
        final byte[] authenticationKey = Helper.V1.generateHkdfAuthenticationKey(key, hkdfSalt);
        final byte[] preAuth = Helper.PAE(Constants.V1.LOCAL_HEADER.getBytes(StandardCharsets.UTF_8), n, c, f);
        final byte[] t2;
        try {
            t2 = Helper.V1.hmacSHA384(authenticationKey, preAuth);
        } catch (InvalidKeyException e) {
            throw new AuthenticationException("Unable to calculate HMAC-SHA384 hash of preAuth data " + new String(preAuth)
                    + " for PASETO message decryption using key " + new String(key), e);
        }
        if(!Arrays.equals(t2, t)){
            throw new AuthenticationException("preAuth hashes don't match");
        }
        final byte[] encryptionKey = Helper.V1.generateHkdfEncryptionKey(key, hkdfSalt);
        final byte[] aesSalt = Arrays.copyOfRange(n, 16, n.length);
        try {
            return new String(Helper.V1.aes256ctrDecrypt(c, aesSalt, encryptionKey), StandardCharsets.UTF_8);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to decrypt data with key " + new String(key), e);
        }
    }

    /**
     * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1sign">Paseto v1.Sign</a>
     */
    @Override
    public String sign(PrivateKey privateKey, byte[] message, byte[] footer) {
        if(!(privateKey instanceof RSAPrivateKey)) {
            throw new IllegalArgumentException("Provided private key is not an RSA private key");
        }
        final byte[] m2 = Helper.PAE(Constants.V1.PUBLIC_HEADER.getBytes(StandardCharsets.UTF_8), message, footer);
        final byte[] signature;
        try {
            signature = Helper.V1.signRsaPss((RSAPrivateKey)privateKey, m2);
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException("PASETO v1.Sign operation failed due to unexpected " + e.getClass().getSimpleName() + " exception", e);
        }
        if(footer.length == 0) {
            return Constants.V1.PUBLIC_HEADER + B64_ENCODER.encodeToString(Helper.concatenate(message, signature));
        }
        return Constants.V1.PUBLIC_HEADER + B64_ENCODER.encodeToString(Helper.concatenate(message, signature)) + "." + B64_ENCODER.encodeToString(footer);
    }

    /**
     * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1verify">Paseto v1.Verify</a>
     */
    @Override
    public String verify(PublicKey publicKey, String token) {
        if(!token.startsWith(Constants.V1.PUBLIC_HEADER)) {
            throw new IllegalArgumentException("Passed token " + token + " is not a valid PASETO v1 public token");
        }
        if(!(publicKey instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("Provided public key is not an RSA public key");
        }
        final String[] parts = token.split("\\.");
        //0 - version, 1 - purpose, 2 - payload, 3 - footer, if present
        final byte[] payload = B64_DECODER.decode(parts[2]);
        final byte[] f;
        if(parts.length == 4) {
            f = B64_DECODER.decode(parts[3]);
        } else {
            f = new byte[0];
        }
        if(payload.length <= 256) {
            throw new IllegalArgumentException("Provided token " + token + " doesn't contain a valid payload for a PASETO v1 public token");
        }
        final byte[] s = Arrays.copyOfRange(payload, payload.length - 256, payload.length);
        final byte[] m = Arrays.copyOf(payload, payload.length - 256);
        final byte[] m2 = Helper.PAE(Constants.V1.PUBLIC_HEADER.getBytes(StandardCharsets.UTF_8), m, f);
        try {
            if(Helper.V1.verifyRsaPssSignature((RSAPublicKey)publicKey, m2, s)) {
                return new String(m, StandardCharsets.UTF_8);
            }
        } catch (InvalidKeyException | SignatureException e) {
            throw new AuthenticationException("Signature verification failed due to an exception of type " + e.getClass().getSimpleName(), e);
        }
        throw new AuthenticationException("Signature verification failed");
    }

    /**
     * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1encrypt">Paseto v1.Encrypt</a>
     */
    @Override
    public String encrypt(byte[] key, byte[] m, byte[] f) {
        final byte[] randomSalt = new byte[32];
        try {
            SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, SECURE_RANDOM_PROVIDER).nextBytes(randomSalt);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Unexpected " + e.getClass().getSimpleName() + " exception for random number generation: " + SECURE_RANDOM_ALGORITHM, e);
        }
        final byte[] n = Helper.V1.getNonce(m, randomSalt);
        final byte[] hkdfSalt = Arrays.copyOfRange(n, 0, 16);
        final byte[] aesSalt = Arrays.copyOfRange(n, 16, 32);
//        for (int i = 0; i < hkdfSalt.length; i++) {
//            hkdfSalt[i] = n[i];
//        }
//        for (int i = 0; i < aesSalt.length; i++) {
//            aesSalt[i] = n[n.length - aesSalt.length + i];
//        }
//        System.arraycopy(n, 16, aesSalt, 0, 16);
        final byte[] encryptionKey = Helper.V1.generateHkdfEncryptionKey(key, hkdfSalt);
        final byte[] authenticationKey = Helper.V1.generateHkdfAuthenticationKey(key, hkdfSalt);
        final byte[] c;
        try {
            c = Helper.V1.aes256ctrEncrypt(m, aesSalt, encryptionKey);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Unable to encrypt message " + new String(m, StandardCharsets.UTF_8)
                    + " using salt " + new String(aesSalt, StandardCharsets.ISO_8859_1) + " for PASETO message encryption", e);
        }
//        final String n = new String(n, StandardCharsets.ISO_8859_1);
//        final String c = new String(encryptedMessage, StandardCharsets.ISO_8859_1);
//        final String f = new String(footer, StandardCharsets.UTF_8);
        final byte[] preAuth = Helper.PAE(Constants.V1.LOCAL_HEADER.getBytes(StandardCharsets.UTF_8), n, c, f);
        final byte[] t;
        try {
            t = Helper.V1.hmacSHA384(authenticationKey, preAuth);
        } catch (InvalidKeyException e) {
            throw new AuthenticationException("Unable to calculate HMAC-SHA384 hash of preAuth data " + new String(preAuth)
                    + " for PASETO message encryption", e);
        }
        final byte[] dataToEncode = Helper.concatenate(n, c, t);
        if(f.length == 0) {
            return Constants.V1.LOCAL_HEADER + B64_ENCODER.encodeToString(dataToEncode);
        }
        return Constants.V1.LOCAL_HEADER + B64_ENCODER.encodeToString(dataToEncode) + "." + B64_ENCODER.encodeToString(f);
    }


}
