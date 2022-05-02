package am.ysu.security.paseto.v1;

import am.ysu.security.paseto.structure.Purpose;
import am.ysu.security.paseto.structure.Version;
import am.ysu.security.paseto.tokens.PasetoToken;
import am.ysu.security.paseto.util.TestingRngProvider;
import am.ysu.security.paseto.utils.protocol.V1ProtocolImplementor;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

//Taken from spec's examples at the end
public class V1LocalTokenTests {

    private static void setupTestingRngProvider() {
        Security.addProvider(new TestingRngProvider());
        V1ProtocolImplementor.setSecureRandomProvider("TestingRngProvider");
        V1ProtocolImplementor.setSecureRandomAlgorithm("NOOP");
    }

    final String payload = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";

    final byte[] keyBytes = new byte[]{
            (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73, (byte)0x74, (byte)0x75, (byte)0x76, (byte)0x77,
            (byte)0x78, (byte)0x79, (byte)0x7a, (byte)0x7b, (byte)0x7c, (byte)0x7d, (byte)0x7e, (byte)0x7f,
            (byte)0x80, (byte)0x81, (byte)0x82, (byte)0x83, (byte)0x84, (byte)0x85, (byte)0x86, (byte)0x87,
            (byte)0x88, (byte)0x89, (byte)0x8a, (byte)0x8b, (byte)0x8c, (byte)0x8d, (byte)0x8e, (byte)0x8f
    };

    @Test
    public void testingRandomLoads() {
        setupTestingRngProvider();
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("NOOP", "TestingRngProvider");
            byte[] testBytes = new byte[20];
            secureRandom.nextBytes(testBytes);
            assertArrayEquals(new byte[20], testBytes);
        } catch (Exception e) {
            fail(e.getMessage());
        }


    }

    /*
        https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#test-vector-v1e1
     */
    @Test
    void performEncryptionTestV1_E1() {
        setupTestingRngProvider();
        final String expectedResult = "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8";
        try {
            final String encrypt = V1ProtocolImplementor.getInstance().encrypt(keyBytes, payload);
            assertEquals(expectedResult, encrypt);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    /*
        https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#test-vector-v1e1
     */
    @Test
    void performDecryptionTestV1_E1() {
        setupTestingRngProvider();
        final String token = "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8";
        try {
            String decrypted = V1ProtocolImplementor.getInstance().decrypt(keyBytes, token);
            assertEquals(payload, decrypted);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void performEncryptionAndDecryptionOnRandomData() {
        final String aPayload = String.format("{\"randomData\":\"%s\"}", UUID.randomUUID());
        try {
            final String token = V1ProtocolImplementor.getInstance().encrypt(keyBytes, aPayload);
            final String decrypted = V1ProtocolImplementor.getInstance().decrypt(keyBytes, token);
            assertEquals(aPayload, decrypted);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testEncryptingAndDecryptingWithRandomKey() {
        final ByteBuffer buffer = ByteBuffer.wrap(new byte[16]);
        final UUID uuid = UUID.randomUUID();
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        final byte[] key = buffer.array();
        final String aPayload = String.format("{\"randomData\":\"%s\"}", UUID.randomUUID());
        try {
            final String token = V1ProtocolImplementor.getInstance().encrypt(key, aPayload);
            final String decrypted = V1ProtocolImplementor.getInstance().decrypt(key, token);
            assertEquals(aPayload, decrypted);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testTokenClassWithRawStrings()
    {
        final ByteBuffer buffer = ByteBuffer.wrap(new byte[16]);
        final UUID uuid = UUID.randomUUID();
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        final byte[] key = buffer.array();
        final String aPayload = String.format("{\"randomData\":\"%s\"}", UUID.randomUUID());
        final String footer = "{\"kid\":\"This is a hostile area\"}";
        try {
            final PasetoToken<String, String> token = new PasetoToken<>(Version.v1, Purpose.LOCAL, aPayload, footer);
            final String formatted = token.encrypt(key);
            final PasetoToken<String, String> decrypted = PasetoToken.parseToken(formatted, key, String.class);
            assertEquals(aPayload, decrypted.getMessage());
            assertEquals(footer, decrypted.getFooter());
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

}
