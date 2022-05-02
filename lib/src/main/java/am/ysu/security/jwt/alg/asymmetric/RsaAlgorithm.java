package am.ysu.security.jwt.alg.asymmetric;

import am.ysu.security.jwt.alg.AlgorithmDefinition;

import java.security.spec.AlgorithmParameterSpec;

public enum RsaAlgorithm implements AlgorithmDefinition {

    RS256("RS256", "SHA256withRSA"),
    RS384("RS384", "SHA384withRSA"),
    RS512("RS512", "SHA512withRSA");

    private final String jwtAlgorithmName;
    private final String javaAlgorithmName;

    RsaAlgorithm(String jwtAlgorithmName, String javaAlgorithmName) {
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

    public static RsaAlgorithm forName(String alg) {
        if(alg.equalsIgnoreCase("RSA")) {
            return RS256;
        }
        for(final RsaAlgorithm rsaAlgorithm : RsaAlgorithm.values()) {
            if(rsaAlgorithm.javaAlgorithmName.equalsIgnoreCase(alg) || rsaAlgorithm.jwtAlgorithmName.equalsIgnoreCase(alg)) {
                return rsaAlgorithm;
            }
        }
        return null;
    }
}
