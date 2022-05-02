package am.ysu.security.security.util.signature;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class SignatureHelper {

    private SignatureHelper(){}

    public static byte[] signRSA(byte[] dataToSign, RSAPrivateKey privateKey, String hashingAlgorithm) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        final Signature signature = Signature.getInstance(hashingAlgorithm + "withRSA");
        signature.initSign(privateKey);
        signature.update(dataToSign);
        return signature.sign();
    }

    public static byte[] signRSA(byte[] dataToSign, RSAPrivateKey privateKey) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
       return signRSA(dataToSign, privateKey, "SHA256");
    }

    public static byte[] sign(byte[] dataToSign, PrivateKey privateKey, String algorithm) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException {
        final Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(dataToSign);
        return signature.sign();
    }

    public static boolean checkRSASignature(byte[] signatureToCheck, RSAPublicKey publicKey, String hashingAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature signature = Signature.getInstance(hashingAlgorithm + "withRSA");
        signature.initVerify(publicKey);
        return signature.verify(signatureToCheck);
    }

    public static boolean checkRSASignature(byte[] signature, RSAPublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return checkRSASignature(signature, publicKey, "SHA256");
    }

    public static boolean checkSignature(byte[] signatureToCheck, PublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        final Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        return signature.verify(signatureToCheck);
    }

}
