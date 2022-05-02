package am.ysu.security.jwt.parsing.error;

public class TokenStructureException extends IllegalArgumentException {
    public TokenStructureException(String message) {
        super(message);
    }
}
