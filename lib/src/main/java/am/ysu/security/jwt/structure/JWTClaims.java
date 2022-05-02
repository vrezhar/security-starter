package am.ysu.security.jwt.structure;

public class JWTClaims {
    public static final String SIGNATURE_ALGORITHM = "alg";
    public static final String TOKEN_TYPE = "typ";
    public static final String ISSUER = "iss";
    public static final String ISSUING_DATE = "iat";
    public static final String EXPIRATION_DATE = "exp";
    public static final String NOT_BEFORE_DATE = "nbe";
    public static final String AUDIENCE = "aud";
    public static final String SUBJECT = "sub";
    public static final String TOKEN_ID = "jti";
    public static final String PUBLIC_KEY_ID = "kid";
    public static final String NONCE = "nonce";
    public static final String NO_SIGNATURE = "none";
    public static final String JSON_WEB_KEY_URL = "jku";
    public static final String AUTHENTICATION_TIME = "auth_time";
    public static final String AUTHORIZATION_CODE_HASH = "c_hash";
    public static final String ACCESS_TOKEN_HASH = "at_hash";

    private JWTClaims() { }
}
