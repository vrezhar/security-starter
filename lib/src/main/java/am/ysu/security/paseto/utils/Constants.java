package am.ysu.security.paseto.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;

public class Constants {
    private Constants() { }

    public static final class V1 {
        public static final String PUBLIC_HEADER = "v1.public.";
        public static final String LOCAL_HEADER = "v1.local.";
        /**
         * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1local">Paseto v1.local</a>
         */
        public static final String ENCRYPTION_ALGORITHM = "AES/CTR/NoPadding";
        public static final String ENCRYPTION_KEY_ALGORITHM = "AES";
        public static final byte[] ENCRYPTION_KEY_HKDF_INFO = "paseto-encryption-key".getBytes(StandardCharsets.UTF_8);
        public static final String HMAC_HASH_ALGORITHM = "HmacSHA384";
        public static final byte[] AUTHENTICATION_KEY_HKDF_INFO = "paseto-auth-key-for-aead".getBytes(StandardCharsets.UTF_8);

        /**
         * @see <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#v1public">Paseto v1.public</a>
         */
        public static final String RSA_SSA_PSS_ALGORITHM = "RSASSA-PSS";
        public static final String PSS_HASH_FUNCTION_ALGORITHM = "SHA-384";
        public static final String PSS_MASK_GENERATION_FUNCTION_NAME = "MGF1";
        public static final MGF1ParameterSpec PSS_MASK_GENERATION_FUNCTION_PARAMETER = MGF1ParameterSpec.SHA384;
        public static final BigInteger REQUIRED_PUBLIC_KEY_EXPONENT_VALUE = BigInteger.valueOf(65537);
        public static final int REQUIRED_KEY_LENGTH_FOR_SIGNING = 2048;

        private V1() { }
    }

    public static final class V2 {
        public static final String PUBLIC_HEADER = "v2.public.";
        public static final String LOCAL_HEADER = "v2.local.";
        public static final String EDWARDS_CURVE_ALGORITHM = "Ed25519";

        private V2(){  }
    }
}
