package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class IssuerValidator extends AbstractJWTValidator {
    private final ArrayList<String> acceptableIssuers;

    public IssuerValidator(String... acceptableIssuers) {
        this(Arrays.asList(acceptableIssuers));
    }

    public IssuerValidator(List<String> issuers) {
        super();
        if(issuers == null || issuers.isEmpty()) {
            throw new IllegalArgumentException("Acceptable issuers' list must not be empty");
        }
        acceptableIssuers = new ArrayList<>(issuers.size());
        acceptableIssuers.addAll(issuers);
    }

    @Override
    public boolean validate(JWT jwt) {
        String issuer = jwt.getIssuer();
        if(issuer == null) {
            setErrorMessage("Issuer claim not present");
            return false;
        }
        if(!acceptableIssuers.contains(issuer)) {
            setErrorMessage("Issuer is not one of acceptable ones: " + acceptableIssuers.toString().replaceAll("\\[", "").replaceAll("]", ""));
            return false;
        }
        return true;
    }
}
