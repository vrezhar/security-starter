package am.ysu.security.paseto.util.v2;

import am.ysu.security.paseto.util.ConstantRandomNonceProvider;

public class V2Provider extends ConstantRandomNonceProvider {
    public V2Provider() {
        super(new byte[] {
                (byte)0xb4cb, (byte)0xfb43, (byte)0xdf4c, (byte)0xe210,
                (byte)0x727d, (byte)0x953e, (byte)0x4a71, (byte)0x3307,
                (byte)0xfa19, (byte)0xbb7d, (byte)0x9f85, (byte)0x0414,
                (byte)0x38d9, (byte)0xe11b, (byte)0x942a, (byte)0x3774,
                (byte)0x1eb9, (byte)0xdbbb, (byte)0xbc04, (byte)0x7c03,
                (byte)0xfd70, (byte)0x604e, (byte)0x0071, (byte)0xf098,
                (byte)0x7e16, (byte)0xb28b, (byte)0x7572, (byte)0x25c1,
                (byte)0x1f00, (byte)0x415d, (byte)0x0e20, (byte)0xb1a2,
        });
    }
}
