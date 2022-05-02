package am.ysu.security.paseto.util;

import java.security.SecureRandomSpi;
import java.util.Arrays;

public class NoopSecureRandomProvider extends SecureRandomSpi {
    @Override
    protected void engineSetSeed(byte[] seed) {

    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        return new byte[numBytes];
    }
}
