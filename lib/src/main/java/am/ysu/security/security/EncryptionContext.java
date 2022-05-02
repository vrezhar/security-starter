package am.ysu.security.security;

import javax.crypto.SecretKey;
import java.security.spec.AlgorithmParameterSpec;

public class EncryptionContext {
    public final String encryptedData;
    public final EncryptionParameters encryptionParameters;

    public EncryptionContext(String encryptedData, EncryptionParameters encryptionParameters) {
        this.encryptedData = encryptedData;
        this.encryptionParameters = encryptionParameters;
    }

    public EncryptionContext(String encryptedData, AlgorithmParameterSpec parameter, SecretKey secretKey) {
        this(encryptedData, new EncryptionParameters(parameter, secretKey));
    }
}
