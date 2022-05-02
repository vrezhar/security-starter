package am.ysu.security.jwt.parsing.error;

public class TokenFormatException extends IllegalArgumentException {
    public TokenFormatException(String message) {
        super(message);
    }
}
