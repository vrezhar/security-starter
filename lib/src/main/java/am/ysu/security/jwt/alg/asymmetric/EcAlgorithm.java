package am.ysu.security.jwt.alg.asymmetric;

import am.ysu.security.jwt.alg.AlgorithmDefinition;

import java.security.spec.AlgorithmParameterSpec;

public enum EcAlgorithm implements AlgorithmDefinition {
    ES256("ES256", "SHA256withECDSA"),
    ES384("ES384", "SHA384withECDSA"),
    ES512("ES512", "SHA512withECDSA");

    private final String jwtAlgorithmName;
    private final String javaAlgorithmName;

    EcAlgorithm(String jwtAlgorithmName, String javaAlgorithmName) {
        this.jwtAlgorithmName = jwtAlgorithmName;
        this.javaAlgorithmName = javaAlgorithmName;
    }

    @Override
    public String getJwtAlgorithmName() {
        return jwtAlgorithmName;
    }

    @Override
    public String getJavaAlgorithmName() {
        return javaAlgorithmName;
    }

    @Override
    public AlgorithmParameterSpec getParameter() {
        return null;
    }

    public static EcAlgorithm forName(String alg) {
        if(alg.equalsIgnoreCase("EC")) {
            return ES256;
        }
        for(final EcAlgorithm ecAlgorithm : EcAlgorithm.values()) {
            if(ecAlgorithm.javaAlgorithmName.equals(alg) || ecAlgorithm.jwtAlgorithmName.equals(alg)) {
                return ecAlgorithm;
            }
        }
        return null;
    }
}
