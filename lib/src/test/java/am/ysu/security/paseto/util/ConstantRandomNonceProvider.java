package am.ysu.security.paseto.util;

import java.security.SecureRandomSpi;

public class ConstantRandomNonceProvider extends SecureRandomSpi
{
    private final byte[] nonce;

//    public ConstantRandomNonceProvider(){
//        this(new byte[]{
//                0x26, 0xf7, 0x55, 0x33, 0x54, 0x48, 0x2a, 0x1d,
//                0x91, 0xd4, 0x78, 0x46, 0x27, 0x85, 0x4b, 0x8d,
//                0xa6, 0xb8, 0x04, 0x2a, 0x79, 0x66, 0x52, 0x3c,
//                0x2b, 0x40, 0x4e, 0x8d, 0xbb, 0xe7, 0xf7, 0xf2
//        });
//    }

    public ConstantRandomNonceProvider(byte[] nonce) {
        this.nonce = nonce;
    }

    @Override
    protected void engineSetSeed(byte[] seed) {

    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        final int nonceLen = nonce.length;
        final int requestedLen = bytes.length;
        if (nonceLen >= requestedLen) {
            System.arraycopy(nonce, 0, bytes, 0, requestedLen);
            return;
        }
        for (int i = 0; i < requestedLen; i++) {
            if(i < nonceLen) {
                bytes[i] = nonce[i];
                continue;
            }
            bytes[i] = 0;
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        return new byte[0];
    }
}
