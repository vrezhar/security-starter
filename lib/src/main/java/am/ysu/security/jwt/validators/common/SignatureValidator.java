package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.alg.AlgorithmDefinition;
import am.ysu.security.jwt.alg.symmetric.HashAlgorithm;
import am.ysu.security.jwt.validators.AbstractJWTValidator;
import am.ysu.security.jwt.validators.JWTValidator;
import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import am.ysu.security.security.util.aes.SecretKeyHelper;
import am.ysu.security.security.util.key.KeyUtils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class SignatureValidator extends AbstractJWTValidator {
    private final JWTValidator coreValidator;

    public SignatureValidator(PublicKey publicKey) {
        this.coreValidator = createValidator(publicKey);
    }

    public SignatureValidator(String key) {
        this.coreValidator = createValidator(key);
    }


    @Override
    public boolean validate(JWT jwt) {
        try {
            final byte[] signature = jwt.getSignature();
            if(signature == null || signature.length == 0) {
                setErrorMessage("Signature missing");
                return false;
            }
            if(!coreValidator.validate(jwt)) {
                setErrorMessage(coreValidator.getErrorMessage());
                return false;
            }
            return true;
        }
        catch (Exception e) {
            setErrorMessage(e.getMessage());
            return false;
        }
    }

    @Deprecated
    public static SignatureValidator undigestedValidator(PublicKey publicKey) {
        return new SignatureValidator(publicKey);
    }

    private static JWTValidator createValidator(String key) {
        return HmacSignatureValidator.getValidator(key);
    }

    private static JWTValidator createValidator(PublicKey key) {
        return AsymmetricSignatureValidator.getValidator(key);
    }

    private static class AsymmetricSignatureValidator extends AbstractJWTValidator {
        private static final Map<String, AsymmetricSignatureValidator> VALIDATORS_CACHE = new LinkedHashMap<>(12);

        private final PublicKey publicKey;

        private AsymmetricSignatureValidator(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public boolean validate(JWT jwt) {
            final var alg = AlgorithmDefinition.extractDefinition(jwt);
            if(alg instanceof HashAlgorithm) {
                setErrorMessage("Algorithm mismatch");
                return false;
            }
            try {
                assert alg != null;
                Signature sig = Signature.getInstance(alg.getJavaAlgorithmName());
                final var paramSpec = alg.getParameter();
                if(paramSpec != null) {
                    sig.setParameter(paramSpec);
                }
                sig.initVerify(publicKey);
                sig.update(jwt.getHeaderAndPayloadBytes());
                final byte[] signatureInToken = jwt.getSignature();
                return sig.verify(signatureInToken);
            } catch(Exception e) {
                setErrorMessage("Invalid key");
                return false;
            }
        }

        public static AsymmetricSignatureValidator getValidator(PublicKey publicKey) {
            return VALIDATORS_CACHE.computeIfAbsent(KeyUtils.calculateFingerPrint(publicKey), key -> new AsymmetricSignatureValidator(publicKey));
        }
    }

    private static class HmacSignatureValidator extends AbstractJWTValidator {
        private static final Map<String, HmacSignatureValidator> VALIDATORS_CACHE = new LinkedHashMap<>(12);

        private final SecretKey secretKey;

        private HmacSignatureValidator(String key) {
            this.secretKey = SecretKeyHelper.generateHmacSecretKey(key);
        }

        @Override
        public boolean validate(JWT jwt) {
            final var alg = AlgorithmDefinition.extractDefinition(jwt);
            if(!(alg instanceof HashAlgorithm)) {
                setErrorMessage("Algorithm mismatch");
                return false;
            }
            try {
                Mac hmac = HashingAndEncryptionHelper.getMac(alg.getJavaAlgorithmName());
                hmac.init(secretKey);
                final byte[] signatureComputed = hmac.doFinal(jwt.getHeaderAndPayloadBytes());
                final byte[] signatureInToken = jwt.getSignature();
                return Arrays.equals(signatureComputed, signatureInToken);
            } catch(Exception e) {
                setErrorMessage("Invalid key");
                return false;
            }
        }

        public static HmacSignatureValidator getValidator(String key) {
            return VALIDATORS_CACHE.computeIfAbsent(key, HmacSignatureValidator::new);
        }
    }
}
