package am.ysu.security.paseto.v2;

import am.ysu.security.paseto.util.TestingRngProvider;
import am.ysu.security.paseto.utils.protocol.V1ProtocolImplementor;
import am.ysu.security.paseto.utils.protocol.V2ProtocolImplementor;
import am.ysu.security.security.util.key.KeyUtils;
import dev.paseto.jpaseto.Pasetos;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/*
    Implementors note; the tests don't work :)
 */
public class V2PublicTests {
    private static void setupTestingRngProvider() {
        Security.addProvider(new TestingRngProvider());
        V1ProtocolImplementor.setSecureRandomProvider("TestingRngProvider");
        V1ProtocolImplementor.setSecureRandomAlgorithm("NOOP");
    }

    private final String message = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}";
    private final byte[] privateKeyBytes = new byte[] {
            (byte)0xb4cb, (byte)0xfb43, (byte)0xdf4c, (byte)0xe210,
            (byte)0x727d, (byte)0x953e, (byte)0x4a71, (byte)0x3307,
            (byte)0xfa19, (byte)0xbb7d, (byte)0x9f85, (byte)0x0414,
            (byte)0x38d9, (byte)0xe11b, (byte)0x942a, (byte)0x3774,
            (byte)0x1eb9, (byte)0xdbbb, (byte)0xbc04, (byte)0x7c03,
            (byte)0xfd70, (byte)0x604e, (byte)0x0071, (byte)0xf098,
            (byte)0x7e16, (byte)0xb28b, (byte)0x7572, (byte)0x25c1,
            (byte)0x1f00, (byte)0x415d, (byte)0x0e20, (byte)0xb1a2,
    };

    private final byte[] publicKeyBytes = new byte[] {
            (byte)0x1eb9, (byte)0xdbbb, (byte)0xbc04, (byte)0x7c03,
            (byte)0xfd70, (byte)0x604e, (byte)0x0071, (byte)0xf098,
            (byte)0x7e16, (byte)0xb28b, (byte)0x7572, (byte)0x25c1,
            (byte)0x1f00, (byte)0x415d, (byte)0x0e20, (byte)0xb1a2,
    };

    @Test
    void testKeyGeneration() {
        setupTestingRngProvider();
        try {
            final KeyPair keyPair = KeyUtils.generateEdECKeyPair(SecureRandom.getInstance("V2S1"));
            final var publicKey = (EdECPublicKey)keyPair.getPublic();
            final var privateKey = (EdECPrivateKey)keyPair.getPrivate();
            final byte[] realPkBytes = publicKey.getPoint().getY().toByteArray();
            final byte[] realPvkBytes = privateKey.getBytes().orElse(new byte[0]);
            assertArrayEquals(realPvkBytes, privateKeyBytes);
            assertEquals(privateKey, KeyUtils.getEdECPrivateKey(privateKeyBytes));
            assertNotNull(realPkBytes);
//            assertEquals(publicKey, KeyUtils.getEdECPublicKey(publicKeyBytes));
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testWithJPasetoV1S1() {
        setupTestingRngProvider();
        final String expectedToken = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
        try {
            final KeyPair keyPair = KeyUtils.generateEdECKeyPair(SecureRandom.getInstance("V2S1"));
            final var privateKey = (EdECPrivateKey)keyPair.getPrivate();
            final byte[] realPvkBytes = privateKey.getBytes().orElse(new byte[0]);
            assertArrayEquals(privateKeyBytes, realPvkBytes);
            String tokenFromJpaseto = Pasetos.V2.PUBLIC.builder()
                    .setPrivateKey(privateKey)
                    .claim("data", "this is a signed message")
                    .claim("exp", "2019-01-01T00:00:00+00:00")
                    .compact();
            String implToken = V2ProtocolImplementor.getInstance().sign(privateKey, message);
            assertEquals(implToken, tokenFromJpaseto);
            assertEquals(expectedToken, tokenFromJpaseto);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testWithJDkGeneratedPrivateKey() {
        setupTestingRngProvider();
        final String expectedToken = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
        try {
            final KeyPair keyPair = KeyUtils.generateEdECKeyPair(SecureRandom.getInstance("V2S1"));
            final var privateKey = (EdECPrivateKey)keyPair.getPrivate();
            final byte[] realPvkBytes = privateKey.getBytes().orElse(new byte[0]);
            assertArrayEquals(privateKeyBytes, realPvkBytes);
            final String signedToken = V2ProtocolImplementor.getInstance().sign(privateKey, message);
            assertEquals(expectedToken, signedToken);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    /*
        https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#test-vector-v2s1
     */
    @Test
    void performTestV2S1() {
        final String expectedToken = "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw";
        try {
            final var privateKey = KeyUtils.getEdECPrivateKey(privateKeyBytes);
            final var publicKey = KeyUtils.getEdECPublicKey(publicKeyBytes);
//            final String resultingToken = V2ProtocolImplementor.getInstance().sign(privateKey, message);
//            assertEquals(expectedToken, resultingToken);
            final String messageVerified = V2ProtocolImplementor.getInstance().verify(publicKey, expectedToken);
            assertEquals(message, messageVerified);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }
}
