package am.ysu.security.hkdf;

import at.favre.lib.crypto.HKDF;
import at.favre.lib.crypto.HkdfMacFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class HkdfTests
{
    @Test
    void testHkdfExtraction()
    {
        final byte[] input = "hello".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] info = "signer-info".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] salt = "1234".getBytes(StandardCharsets.ISO_8859_1);
        try {
            final byte[] okm = am.ysu.security.paseto.utils.HKDF.computeOkm("HmacSHA384", input, info, salt, 255);
            assertNotNull(okm);
            assertEquals(255, okm.length);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    void testAgainstAnotherLibrary() {
        final byte[] input = "hello".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] info = "signer-info".getBytes(StandardCharsets.ISO_8859_1);
        final byte[] salt = "1234".getBytes(StandardCharsets.ISO_8859_1);
        try {
            final var hkdf = am.ysu.security.paseto.utils.HKDF.getInstance("HmacSHA384");
            final HKDF hmacSHA384 = HKDF.from(new HkdfMacFactory.Default("HmacSHA384"));
            hkdf.updateIkm(input);
            byte[] prk = hkdf.extractWithSalt(salt);
            byte[] prkFromLib = hmacSHA384.extract(salt, input);
            assertArrayEquals(prkFromLib, prk);
            final byte[] okm = hkdf.expand(info, 32);
            assertEquals(32, okm.length);
            final byte[] okmFromLib = hmacSHA384.expand(prkFromLib, info, 32);
            assertEquals( 32, okmFromLib.length);
            assertArrayEquals(okmFromLib, okm);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }
}
