package am.ysu.security.paseto.utils;

import am.ysu.security.security.util.aes.SecretKeyHelper;
import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Objects;

public final class Helper {
    private Helper() { }

    /**
     @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#pae-definition">PAE function definition</a>
     */
    public static byte[] PAE(byte[]... pieces) {
        final int size = Objects.requireNonNull(pieces, "PASETO fragment's array must not be null").length;
        try(final ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            output.write(LE64(size));
            for (byte[] piece : pieces) {
                output.write(LE64(piece.length));
                output.write(piece);
            }
            return output.toByteArray();
        } catch (IOException ioException) {
            throw new RuntimeException("Unexpected IOException", ioException);
        }
    }

    /**
     @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#pae-definition">PAE function definition</a>
     */
    public static byte[] LE64(long n) {
        long unsignedLong = n & Long.MAX_VALUE;
        ByteBuffer buffer = ByteBuffer.allocate(java.lang.Long.BYTES);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(unsignedLong);
        return buffer.array();
    }

    public static byte[] concatenate(byte[]... parts) {
        final ByteBuffer byteBuffer = ByteBuffer.allocate(Arrays.stream(parts).mapToInt(array -> array.length).sum());
        for(byte[] part : parts) {
            byteBuffer.put(part);
        }
        return byteBuffer.array();
    }

    public static ObjectMapper createObjectMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        return mapper;
    }

    public static final class V1 {

        private V1() { }

        /**
         @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1getnonce">v1.GetNonce</a>
         */
        public static byte[] getNonce(byte[] message, byte[] key) {
            final Mac mac;
            try {
                mac = HashingAndEncryptionHelper.getMac(Constants.V1.HMAC_HASH_ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to instantiate algorithm " + Constants.V1.HMAC_HASH_ALGORITHM + " for message authentication", e);
            }
            try {
                mac.init(SecretKeyHelper.generateSecretKey(key, Constants.V1.HMAC_HASH_ALGORITHM));
                final byte[] output = new byte[32];
                final byte[] hmacResult = mac.doFinal(message);
                assert hmacResult.length >= 32;
                System.arraycopy(hmacResult, 0, output, 0, 32);
                return output;
            } catch (InvalidKeyException e) {
                throw new RuntimeException("Unable to initiate algorithm " + Constants.V1.HMAC_HASH_ALGORITHM + " for message authentication", e);
            }
        }

        public static byte[] aes256ctrEncrypt(byte[] message, byte[] nonce, byte[] encryptionKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(Constants.V1.ENCRYPTION_ALGORITHM);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException("Unexpected " + e.getClass().getSimpleName() + " occurred during PASETO message encryption cipher generation", e);
            }
            final IvParameterSpec iv = new IvParameterSpec(nonce);
            try {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeyHelper.generateSecretKey(encryptionKey, Constants.V1.ENCRYPTION_KEY_ALGORITHM), iv);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Unexpected InvalidAlgorithmParameterException for nonce " + new String(nonce) + " during PASETO message cipher initialization");
            }
            return cipher.doFinal(message);
        }

        public static byte[] aes256ctrDecrypt(byte[] message, byte[] nonce, byte[] encryptionKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(Constants.V1.ENCRYPTION_ALGORITHM);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new RuntimeException("Unexpected " + e.getClass().getSimpleName() + " occurred during PASETO message decryption cipher generation", e);
            }
            final IvParameterSpec iv = new IvParameterSpec(nonce);
            try {
                cipher.init(Cipher.DECRYPT_MODE, SecretKeyHelper.generateSecretKey(encryptionKey, Constants.V1.ENCRYPTION_KEY_ALGORITHM), iv);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Unexpected InvalidAlgorithmParameterException for nonce " + new String(nonce) + " during PASETO message decryption cipher initialization");
            }
            return cipher.doFinal(message);
        }

        public static byte[] generateHkdfKeyOrThrow(byte[] key, byte[] info, byte[] salt, String message) {
            try {
                return HKDF.computeOkm(Constants.V1.HMAC_HASH_ALGORITHM, key, info, salt, 32);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(message);
            }
        }

        public static byte[] generateHkdfAuthenticationKey(byte[] key, byte[] salt) {
            try {
                return HKDF.computeOkm(Constants.V1.HMAC_HASH_ALGORITHM, key, Constants.V1.AUTHENTICATION_KEY_HKDF_INFO, salt, 32);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Unexpected NoSuchAlgorithmException occurred during PASETO authentication key calculation");
            }
        }

        public static byte[] generateHkdfEncryptionKey(byte[] key, byte[] salt) {
            try {
                return HKDF.computeOkm(Constants.V1.HMAC_HASH_ALGORITHM, key, Constants.V1.ENCRYPTION_KEY_HKDF_INFO, salt, 32);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Unexpected NoSuchAlgorithmException occurred during PASETO encryption key calculation");
            }
        }

        public static byte[] hmacSHA384(byte[] authenticationKey, byte[] preAuth) throws InvalidKeyException {
            final Mac hmac;
            try {
                hmac = Mac.getInstance(Constants.V1.HMAC_HASH_ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unexpected NoSuchAlgorithmException occurred during PASETO authentication MAC generation", e);
            }
            hmac.init(SecretKeyHelper.generateSecretKey(authenticationKey, Constants.V1.HMAC_HASH_ALGORITHM));
            return hmac.doFinal(preAuth);
        }

        public static byte[] signRsaPss(RSAPrivateKey privateKey, byte[] dataToSign) throws InvalidKeyException, SignatureException {
            final Signature signature = initSignature(privateKey);
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        }

        public static boolean verifyRsaPssSignature(RSAPublicKey publicKey, byte[] dataToSign, byte[] signature) throws InvalidKeyException, SignatureException {
            final Signature sig = initSignature(publicKey);
            sig.initVerify(publicKey);
            sig.update(dataToSign);
            return sig.verify(signature);
        }

        public static boolean checkKeyCompatabilityWithStandard(RSAPublicKey publicKey) {
            return publicKey.getPublicExponent().equals(Constants.V1.REQUIRED_PUBLIC_KEY_EXPONENT_VALUE) &&
                    publicKey.getModulus().bitLength() == Constants.V1.REQUIRED_KEY_LENGTH_FOR_SIGNING;
        }

        public static boolean checkKeyCompatabilityWithStandard(RSAPrivateKey privateKey) {
            return privateKey.getModulus().bitLength() == Constants.V1.REQUIRED_KEY_LENGTH_FOR_SIGNING;
        }

        public static AlgorithmParameterSpec createPssParameterSpec() {
            return new PSSParameterSpec(
                    Constants.V1.PSS_HASH_FUNCTION_ALGORITHM,
                    Constants.V1.PSS_MASK_GENERATION_FUNCTION_NAME,
                    Constants.V1.PSS_MASK_GENERATION_FUNCTION_PARAMETER,
                    0, 1
            );
        }

        private static Signature initSignature(Key key) throws InvalidKeyException {
            if(key instanceof RSAPublicKey) {
                if (!checkKeyCompatabilityWithStandard((RSAPublicKey)key)) {
                    throw new InvalidKeyException("Key doesn't match PASETO v1 requirements");
                }
            } else if(key instanceof RSAPrivateKey) {
                if (!checkKeyCompatabilityWithStandard((RSAPrivateKey)key)) {
                    throw new InvalidKeyException("Key doesn't match PASETO v1 requirements");
                }
            } else {
                throw new IllegalArgumentException("Provided key is not an RSA key");
            }
            final Signature sig;
            try {
                sig = Signature.getInstance(Constants.V1.RSA_SSA_PSS_ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("RSA-SSA with PSS padding not available", e);
            }
            try {
                sig.setParameter(createPssParameterSpec());
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException("Unable to initialize RSA-PSS parameter with hash algorithm SHA384 and mask generation function MGF1+SHA384", e);
            }
            return sig;
        }
    }

    public static class V2 {
        public static byte[] signEd25519(PrivateKey privateKey, byte[] dataToSign) throws InvalidKeyException, SignatureException {
            if(!(privateKey instanceof EdECPrivateKey)) {
                throw new IllegalArgumentException("Provided key is not a valid EdEC key");
            }
            final Signature signature;
            try {
                signature = Signature.getInstance(Constants.V2.EDWARDS_CURVE_ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to instantiate Ed25519 signature instance, check the JRE version", e);
            }
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        }

        public static boolean verifyEd25519(PublicKey publicKey, byte[] signedData, byte[] signature) throws InvalidKeyException, SignatureException {
            if(!(publicKey instanceof EdECPublicKey)) {
                throw new IllegalArgumentException("Provided key is not a valid EdEC key");
            }
            final Signature sig;
            try {
                sig = Signature.getInstance(Constants.V2.EDWARDS_CURVE_ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to instantiate Ed25519 signature instance, check the JRE version", e);
            }
            sig.initVerify(publicKey);
            sig.update(signedData);
            return sig.verify(signature);
        }

        private V2() { }
    }
}
