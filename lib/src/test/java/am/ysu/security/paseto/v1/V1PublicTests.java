package am.ysu.security.paseto.v1;

import am.ysu.security.paseto.utils.protocol.V1ProtocolImplementor;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

public class V1PublicTests
{
    private final String messageToSign = "{\"message\": \"This is a signed message\"}";
    private final String footer = "{\"fdata\":\"this is a hostile area\"}";

    @Test
    void testJdkDefaultRSASSA_PSS() {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            final KeyPair keyPair = kpg.generateKeyPair();
            assertNotNull(keyPair);
            final Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 0, 1));
            sig.initSign(keyPair.getPrivate());
            sig.update(messageToSign.getBytes(StandardCharsets.UTF_8));
            final byte[] signature = sig.sign();
            assertNotNull(signature);
            final Signature verifSig = Signature.getInstance("RSASSA-PSS");
            verifSig.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 0, 1));
            verifSig.initVerify(keyPair.getPublic());
            verifSig.update(messageToSign.getBytes(StandardCharsets.UTF_8));
            assertTrue(verifSig.verify(signature));
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testProtocolImplementorWithoutAFooter() {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            final KeyPair keyPair = kpg.generateKeyPair();
            assertNotNull(keyPair);
            String signed = V1ProtocolImplementor.getInstance().sign(keyPair.getPrivate(), messageToSign);
            String verified = V1ProtocolImplementor.getInstance().verify(keyPair.getPublic(), signed);
            assertEquals(messageToSign, verified);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testProtocolImplementorWithoutFooter() {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            final KeyPair keyPair = kpg.generateKeyPair();
            assertNotNull(keyPair);
            String signed = V1ProtocolImplementor.getInstance().sign(keyPair.getPrivate(), messageToSign, footer);
            String verified = V1ProtocolImplementor.getInstance().verify(keyPair.getPublic(), signed);
            assertEquals(messageToSign, verified);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }
}
