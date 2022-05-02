package am.ysu.security.jwt.alg.asymmetric;

import am.ysu.security.jwt.alg.AlgorithmDefinition;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public enum RsaPssAlgorithm implements AlgorithmDefinition {
    PS256(
            "PS256", "RSASSA-PSS",
            new PSSParameterSpec(
                    MGF1ParameterSpec.SHA256.getDigestAlgorithm(),
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    32, 1
            )
    ),
    PS384(
            "PS384", "RSASSA-PSS",
            new PSSParameterSpec(
                    MGF1ParameterSpec.SHA512.getDigestAlgorithm(),
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    48, 1
            )
    ),
    PS512(
            "PS512", "RSASSA-PSS",
            new PSSParameterSpec(
                    MGF1ParameterSpec.SHA512.getDigestAlgorithm(),
                    "MGF1",
                    MGF1ParameterSpec.SHA512,
                    64, 1
            )
    );

    private final String jwtAlgorithmName;
    private final String javaAlgorithmName;
    private final AlgorithmParameterSpec parameterSpec;

    RsaPssAlgorithm(String jwtAlgorithmName, String javaAlgorithmName, AlgorithmParameterSpec parameterSpec) {
        this.jwtAlgorithmName = jwtAlgorithmName;
        this.javaAlgorithmName = javaAlgorithmName;
        this.parameterSpec = parameterSpec;
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
        return parameterSpec;
    }

    public static RsaPssAlgorithm forName(String alg) {
        if(alg.equalsIgnoreCase("RSASSA-PSS")) {
            return PS256;
        }
        for(final RsaPssAlgorithm rsaPssAlgorithm : RsaPssAlgorithm.values()) {
            if(rsaPssAlgorithm.javaAlgorithmName.equals(alg) || rsaPssAlgorithm.jwtAlgorithmName.equals(alg)) {
                return rsaPssAlgorithm;
            }
        }
        return null;
    }
}
