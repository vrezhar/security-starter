package am.ysu.security.jwt.validators.composite;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.JWTValidator;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CompositeJWTValidator extends AbstractJWTValidator {
    private final List<JWTValidator> validators;

    public CompositeJWTValidator() {
        validators = new ArrayList<>(4);
    }

    public CompositeJWTValidator(List<JWTValidator> validators) {
        if(validators == null || validators.isEmpty()){
            throw new IllegalArgumentException("Validator list shouldn't be null");
        }
        this.validators = new ArrayList<>(validators.size());
        this.validators.addAll(validators);
    }

    public CompositeJWTValidator(JWTValidator... validators) {
        this(Arrays.asList(validators));
    }

    public void addToValidators(JWTValidator... validators) {
        this.validators.addAll(Arrays.asList(validators));
    }

    public void addToValidators(JWTValidator validator) {
        this.validators.add(validator);
    }

    @Override
    public boolean validate(JWT jwt) {
        for(JWTValidator validator : validators) {
            if(!validator.validate(jwt)) {
                setErrorMessage(validator.getErrorMessage());
                return false;
            }
        }
        return true;
    }
}
