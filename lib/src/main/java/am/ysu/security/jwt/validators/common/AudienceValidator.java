package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AudienceValidator extends AbstractJWTValidator {
    private final ArrayList<String> acceptedAudience;

    public AudienceValidator(String... acceptableIssuers) {
        this(Arrays.asList(acceptableIssuers));
    }

    public AudienceValidator(List<String> issuers) {
        super();
        if(issuers == null || issuers.isEmpty()){
            throw new IllegalArgumentException("Acceptable issuers' list must not be empty");
        }
        acceptedAudience = new ArrayList<>(issuers.size());
        acceptedAudience.addAll(issuers);
        acceptedAudience.add("*");
    }

    @Override
    public boolean validate(JWT jwt) {
        try {
            List<String> audience = jwt.getAudience();
            if(audience == null || audience.isEmpty()) {
                setErrorMessage("Audience claim empty or not present");
                return false;
            }
            for(String acceptedAudienceValue : acceptedAudience) {
                if(audience.contains(acceptedAudienceValue)) {
                    return true;
                }
            }
            setErrorMessage("Audience claim doesn't contain any of acceptable audiences " + acceptedAudience.toString().replaceAll("\\[", "").replaceAll("]", ""));
            return false;
        }
        catch (Exception e) {
            setErrorMessage(e.getMessage());
            return false;
        }
    }
}
