package am.ysu.security.jwk;

public class JWKFields {
    public static final String KEY_ID = "kid";
    public static final String KEY_USAGE = "use";
    public static final String USAGE_FOR_SIGNING = "sig";
    public static final String KEY_TYPE = "kty";
    public static final String RSA_KEY_TYPE = "RSA";
    public static final String ELLIPTIC_CURVE_KEY_TYPE = "EC";
    public static final String ALGORITHM = "alg";
    public static final String ELLIPTIC_CURVE_TYPE = "crv";
    public static final String DEFAULT_ELLIPTIC_CURVE_TYPE = "P-256";
    public static final String DEFAULT_RSA_ALGORITHM = "RS256";
    public static final String DEFAULT_ELLIPTIC_CURVE_ALGORITHM = "ES256";
    public static final String PUBLIC_EXPONENT = "e";
    public static final String MODULUS = "n";
    public static final String EC_POINT_X = "x";
    public static final String EC_POINT_Y = "y";

    private JWKFields() { }
}
