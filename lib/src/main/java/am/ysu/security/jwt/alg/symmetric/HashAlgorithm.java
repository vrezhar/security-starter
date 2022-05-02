package am.ysu.security.jwt.alg.symmetric;

import am.ysu.security.jwt.alg.AlgorithmDefinition;

import java.security.spec.AlgorithmParameterSpec;

public enum HashAlgorithm implements AlgorithmDefinition {

    HS256("HS256", "HmacSHA256"),
    HS384("HS384", "HmacSHA384"),
    HS512("HS512", "HmacSHA512");

    private final String jwtAlgorithmName;
    private final String javaAlgorithmName;

    HashAlgorithm(String jwtAlgorithmName, String javaAlgorithmName) {
        this.jwtAlgorithmName = jwtAlgorithmName;
        this.javaAlgorithmName = javaAlgorithmName;
    }

    public String getJwtAlgorithmName() {
        return jwtAlgorithmName;
    }

    public String getJavaAlgorithmName() {
        return javaAlgorithmName;
    }

    @Override
    public AlgorithmParameterSpec getParameter() {
        return null;
    }
}
