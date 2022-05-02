package am.ysu.security.jwt.alg;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.alg.asymmetric.EcAlgorithm;
import am.ysu.security.jwt.alg.asymmetric.RsaAlgorithm;
import am.ysu.security.jwt.alg.asymmetric.RsaPssAlgorithm;
import am.ysu.security.jwt.alg.symmetric.HashAlgorithm;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

public interface AlgorithmDefinition {

    String getJwtAlgorithmName();

    String getJavaAlgorithmName();

    AlgorithmParameterSpec getParameter();

    static AlgorithmDefinition extractDefinition(JWT jwt) {
        String alg = jwt.getSignatureAlgorithm();
        if(alg == null) {
            throw new IllegalArgumentException("No 'alg' claim present in the header");
        }
        if(alg.equalsIgnoreCase("none")) {
            return NoneAlgorithm.INSTANCE;
        }
        return switch (alg.charAt(0)) {
            case 'R' -> RsaAlgorithm.valueOf(alg);
            case 'E' -> EcAlgorithm.valueOf(alg);
            case 'P' -> RsaPssAlgorithm.valueOf(alg);
            case 'H' -> HashAlgorithm.valueOf(alg);
            default -> throw new IllegalStateException("Unsupported algorithm [" + alg + "]");
        };
    }

    static AlgorithmDefinition forKeyAndAlgorithm(PublicKey publicKey, String algorithm) {
        if(publicKey instanceof RSAPublicKey) {
            switch (algorithm) {
                case "SHA256", "SHA-256", "sha-256", "sha256" -> {
                    return RsaAlgorithm.RS256;
                }
                case "SHA384", "SHA-384", "sha-384", "sha384" -> {
                    return RsaAlgorithm.RS384;
                }
                case "SHA512", "SHA-512", "sha-512", "sha512" -> {
                    return RsaAlgorithm.RS512;
                }
                default -> {
                    AlgorithmDefinition definition = RsaPssAlgorithm.forName(algorithm);
                    if(definition == null) {
                        definition = RsaAlgorithm.forName(algorithm);
                        if(definition != null) {
                            return definition;
                        }
                    }
                    throw new IllegalArgumentException("Unknown algorithm [" + algorithm + "]");
                }
            }
        }
        if(publicKey instanceof ECPublicKey) {
            switch (algorithm) {
                case "SHA256", "SHA-256", "sha-256", "sha256" -> {
                    return EcAlgorithm.ES256;
                }
                case "SHA384", "SHA-384", "sha-384", "sha384" -> {
                    return EcAlgorithm.ES384;
                }
                case "SHA512", "SHA-512", "sha-512", "sha512" -> {
                    return EcAlgorithm.ES512;
                }
                default -> {
                    final var definition = EcAlgorithm.forName(algorithm);
                    if(definition != null) {
                        return definition;
                    }
                    throw new IllegalArgumentException("Unknown algorithm [" + algorithm + "]");
                }
            }
        }
        throw new IllegalArgumentException("Unsupported public key type [" + publicKey.getClass().getSimpleName() + "]");
    }

    class NoneAlgorithm implements AlgorithmDefinition {

        static NoneAlgorithm INSTANCE = new NoneAlgorithm();

        private NoneAlgorithm() { }

        @Override
        public String getJwtAlgorithmName() {
            return null;
        }

        @Override
        public String getJavaAlgorithmName() {
            return "none";
        }

        @Override
        public AlgorithmParameterSpec getParameter() {
            return null;
        }
    }
}
