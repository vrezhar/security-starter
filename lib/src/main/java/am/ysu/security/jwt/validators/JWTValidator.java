package am.ysu.security.jwt.validators;

import am.ysu.security.jwt.JWT;

public interface JWTValidator {
    boolean validate(JWT jwt);

    String getErrorMessage();
}
