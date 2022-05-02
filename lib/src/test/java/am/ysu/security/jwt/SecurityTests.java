package am.ysu.security.jwt;

import am.ysu.security.security.EncryptionParameters;
import am.ysu.security.security.util.aes.HashingAndEncryptionHelper;
import am.ysu.security.security.util.aes.SecretKeyHelper;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class SecurityTests {
    @Test
    void testEncryptionAndDecryption() {
        IvParameterSpec iv = SecretKeyHelper.generateIVParameterSpec();
        String testData = "test";
        byte[] salt = new byte[]{
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
        };
        String password = UUID.randomUUID().toString();
        try {
            String encrypted = HashingAndEncryptionHelper.encryptUsingPassword(testData, password, salt, iv).encryptedData;
            assertNotNull(encrypted);
            assertNotEquals(encrypted, testData);
            String decrypted = HashingAndEncryptionHelper.decrypt(encrypted, new EncryptionParameters(iv, password, salt));
            assertNotNull(decrypted);
            assertEquals(decrypted, testData);
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }
}
