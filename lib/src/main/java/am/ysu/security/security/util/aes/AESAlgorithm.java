package am.ysu.security.security.util.aes;

import java.security.spec.AlgorithmParameterSpec;

public enum AESAlgorithm {
    CBC_WITH_PKCS5_PADDING("AES/CBC/PKCS5Padding", SecretKeyHelper.generateIVParameterSpec()),
    CFB_WITH_PKCS5_PADDING("AES/CFB/PKCS5Padding", SecretKeyHelper.generateIVParameterSpec()),
    OFB_WITH_PKCS5_PADDING("AES/OFB/PKCS5Padding", SecretKeyHelper.generateIVParameterSpec()),
    GCM_WITH_NO_PADDING("AES/GCM/NoPadding", SecretKeyHelper.generateGCMParameterSpec(12));

    public final String value;
    public final AlgorithmParameterSpec parameter;

    AESAlgorithm(String value, AlgorithmParameterSpec parameter) {
        this.value = value;
        this.parameter = parameter;
    }
}
