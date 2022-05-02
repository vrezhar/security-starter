package am.ysu.security.paseto.utils;

import am.ysu.security.security.util.aes.SecretKeyHelper;

import javax.crypto.Mac;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

public class HKDF {
    private final Mac mac;
    private byte[] inputKeyingMaterial;
    private byte[] info;
    private byte[] pseudoRandomKey;
    private final int hashLength;
    private final String algorithm;

    private HKDF(Mac mac, int hashLength, String algorithm) {
        this.mac = mac;
        this.hashLength = hashLength;
        this.algorithm = algorithm;
    }

    public void updateIkm(byte[] ikm) {
        Objects.requireNonNull(ikm, "HKDF input keying message should not be null");
        if(pseudoRandomKey != null) {
            throw new IllegalStateException("HKDF key already extracted");
        }
        if(this.inputKeyingMaterial != null) {
            this.inputKeyingMaterial = ByteBuffer
                    .allocate(this.inputKeyingMaterial.length + ikm.length)
                    .put(this.inputKeyingMaterial)
                    .put(ikm)
                    .array();
        } else {
            this.inputKeyingMaterial = ikm;
        }
    }

    public void updateIkm(String ikm) {
        updateIkm(ikm.getBytes(StandardCharsets.ISO_8859_1));
    }

    public void updateInfo(byte[] info) {
//        if(pseudoRandomKey != null) {
//            throw new IllegalStateException("HKDF key already extracted");
//        }
        Objects.requireNonNull(info, "HKDF info should not be null");
        if(this.info != null) {
            this.info = ByteBuffer
                    .allocate(this.info.length + info.length)
                    .put(this.info)
                    .put(info)
                    .array();
        } else {
            this.info = info;
        }
    }

    public void updateInfo(String info) {
        updateInfo(info.getBytes(StandardCharsets.ISO_8859_1));
    }

    public byte[] extractWithSalt(byte[] ikm, byte[] salt) throws InvalidKeyException {
        updateIkm(ikm);
        return doExtract(salt);
    }

    public byte[] extract(byte[] ikm) throws InvalidKeyException {
        updateIkm(ikm);
        return doExtract(new byte[hashLength]);
    }

    public byte[] extract() throws InvalidKeyException {
        if(inputKeyingMaterial == null) {
            throw new IllegalStateException("Input keying material missing for HKDF");
        }
        return doExtract(new byte[hashLength]);
    }

    public byte[] extractWithSalt(byte[] salt) throws InvalidKeyException {
        if(inputKeyingMaterial == null) {
            throw new IllegalStateException("Input keying material missing for HKDF");
        }
        return doExtract(salt);
    }

    public byte[] expand(byte[] pseudoRandomKey, byte[] info, int length) throws InvalidKeyException {
        if(length > 255 * hashLength) {
            throw new IllegalArgumentException("HKDF expansion parameter L must not be exceeding 255*HashLen(" + length + " was requested)");
        }
        this.info = info;
        this.pseudoRandomKey = pseudoRandomKey;
        return doExpand(length);
    }

    public byte[] expand(byte[] info, int length) throws InvalidKeyException {
        if(length > 255 * hashLength) {
            throw new IllegalArgumentException("HKDF expansion parameter L must not be exceeding 255*HashLen(" + length + " was requested)");
        }
        if(pseudoRandomKey == null) {
            throw new IllegalStateException("HKDF pseudo-random key not generated");
        }
        this.info = info;
        return doExpand(length);
    }

    public byte[] expand(int length) throws InvalidKeyException {
        if(length > 255 * hashLength) {
            throw new IllegalArgumentException("HKDF expansion parameter L must not be exceeding 255*HashLen(" + length + " was requested)");
        }
        if(info == null) {
            throw new IllegalStateException("HKDF info not set");
        }
        if(pseudoRandomKey == null) {
            throw new IllegalStateException("Pseudo-random key for HKDF not set");
        }
        return doExpand(length);
    }

    private byte[] doExpand(int length) throws InvalidKeyException {
        final Mac hmac;
        try {
            hmac = Mac.getInstance(algorithm);
        } catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException("Unexpected NoSuchAlgorithmException encountered when trying to expand HKDF", nse);
        }
        hmac.init(SecretKeyHelper.generateSecretKey(pseudoRandomKey, algorithm));
        final int N = (int) Math.ceil((double)length/(double)hashLength);
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(hashLength * N);
        byte[] Ti = "".getBytes(StandardCharsets.ISO_8859_1); //T[0] - empty string
        for (int i = 0; i < N; i++) {
            hmac.update(Ti);
            hmac.update(info);
            hmac.update((byte)(i + 1));
            Ti = hmac.doFinal();
            try {
                byteArrayOutputStream.write(Ti);
            } catch (IOException e) {
                //shouldn't be thrown
            }
        }

        return Arrays.copyOfRange(byteArrayOutputStream.toByteArray(), 0, length);
    }

    private byte[] doExtract(byte[] salt) throws InvalidKeyException {
        mac.init(SecretKeyHelper.generateSecretKey(salt, algorithm));
        pseudoRandomKey = mac.doFinal(inputKeyingMaterial);
        return pseudoRandomKey;
    }

    public static HKDF getInstance(String algorithm) throws NoSuchAlgorithmException {
        final Mac mac = Mac.getInstance(algorithm);
        return new HKDF(mac, mac.getMacLength(), algorithm);
    }

    public static byte[] computeOkm(String algorithm, byte[] inputKey, byte[] info, byte[] salt, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        if(length > 255) {
            throw new IllegalArgumentException("HKDF expansion parameter L must not be exceeding 255*HashLen(" + length + " was requested)");
        }
        final HKDF hkdf = getInstance(algorithm);
        final byte[] pkr = hkdf.extractWithSalt(inputKey, salt);
        //maybe log the pseudo-random key at debug
        return hkdf.expand(info, length);
    }

    public static byte[] computeOkm(String algorithm, String inputKey, String info, byte[] salt, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        return computeOkm(algorithm, inputKey.getBytes(StandardCharsets.ISO_8859_1), info.getBytes(StandardCharsets.ISO_8859_1), salt, length);
    }

    public static byte[] computeOkm(String algorithm, byte[] inputKey, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        if(length > 255) {
            throw new IllegalArgumentException("HKDF expansion parameter L must not be exceeding 255*HashLen(" + length + " was requested)");
        }
        final HKDF hkdf = getInstance(algorithm);
        final byte[] pkr = hkdf.extract(inputKey);
        //maybe log the pseudo-random key at debug
        return hkdf.expand(info, length);
    }

    public static byte[] computeOkm(String algorithm, String inputKey, String info, int length) throws NoSuchAlgorithmException, InvalidKeyException {
        return computeOkm(algorithm, inputKey.getBytes(StandardCharsets.ISO_8859_1), info.getBytes(StandardCharsets.ISO_8859_1), length);
    }

}
