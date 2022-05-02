package am.ysu.security.jwt.validators;

public abstract class AbstractJWTValidator implements JWTValidator {
    private final ThreadLocal<String> errorMessage;

    public AbstractJWTValidator() {
        this.errorMessage = new ThreadLocal<>();
    }

    public String getErrorMessage() {
        return errorMessage.get();
    }

    public void setErrorMessage(String message) {
        this.errorMessage.set(message);
    }
}
