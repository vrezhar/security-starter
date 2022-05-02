package am.ysu.security.jwt.validators;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.common.AudienceValidator;
import am.ysu.security.jwt.validators.common.IssuerValidator;
import am.ysu.security.jwt.validators.common.SignatureValidator;
import am.ysu.security.jwt.validators.composite.CompositeJWTValidator;
import am.ysu.security.jwt.validators.common.RemoteTokenValidator;

import java.security.PublicKey;
import java.util.List;
import java.util.function.Function;

public class JWTValidatorBuilder {
    private final CompositeJWTValidator validator;

    private JWTValidatorBuilder() {
        this.validator = new CompositeJWTValidator();
    }

    public JWTValidator create() {
        return validator;
    }

    public JWTValidatorBuilder withSignatureVerificationKey(PublicKey publicKey) {
        this.validator.addToValidators(new SignatureValidator(publicKey));
        return this;
    }

    public JWTValidatorBuilder withAcceptableAudience(List<String> audience) {
        this.validator.addToValidators(new AudienceValidator(audience));
        return this;
    }

    public JWTValidatorBuilder withValidIssuers(String... issuers) {
        this.validator.addToValidators(new IssuerValidator(issuers));
        return this;
    }

    public JWTValidatorBuilder withRemoteValidation(String authorizationServerUrl) {
        this.validator.addToValidators(new RemoteTokenValidator(authorizationServerUrl));
        return this;
    }

    public JWTValidatorBuilder withCustomValidator(String errorMessage, Function<JWT, Boolean> validator) {
        this.validator.addToValidators(new CustomValidator(validator, errorMessage));
        return this;
    }

    public JWTValidatorBuilder withCustomValidator(JWTValidator validator) {
        this.validator.addToValidators(validator);
        return this;
    }

    public JWTValidatorBuilder withClaimValidator(String errorMessage, String claim, Function<Object, Boolean> validator) {
        this.validator.addToValidators(new CustomClaimValidator(claim, validator, errorMessage));
        return this;
    }

    public JWTValidatorBuilder requiringPresenceOfClaim(String claim) {
        this.validator.addToValidators(new PresenceValidator(claim, true));
        return this;
    }

    public JWTValidatorBuilder requiringAbsenceOfClaim(String claim) {
        this.validator.addToValidators(new PresenceValidator(claim, false));
        return this;
    }

    public JWTValidatorBuilder withCustomValidator(Function<JWT, Boolean> validator) {
        return withCustomValidator("Custom validation failed", validator);
    }

    public JWTValidatorBuilder withClaimValidator(String claim, Function<Object, Boolean> validator) {
        return withClaimValidator(claim + " claim is invalid", claim, validator);
    }

    public static JWTValidatorBuilder newValidator() {
        return new JWTValidatorBuilder();
    }

    private static class CustomValidator extends AbstractJWTValidator {
        private final String errorMessage;
        private final Function<JWT, Boolean> validator;

        CustomValidator(Function<JWT, Boolean> validator, String errorMessage) {
            this.validator = validator;
            this.errorMessage = errorMessage;
        }

        @Override
        public boolean validate(JWT jwt) {
            if(!validator.apply(jwt)) {
                setErrorMessage(errorMessage);
                return false;
            }
            return true;
        }
    }

    private static class CustomClaimValidator extends AbstractJWTValidator {
        private final String errorMessage;
        private final String claimToValidate;
        private final Function<Object, Boolean> validator;

        CustomClaimValidator(String claimToValidate, Function<Object, Boolean> validator, String errorMessage) {
            this.claimToValidate = claimToValidate;
            this.validator = validator;
            this.errorMessage = errorMessage;
        }

        @Override
        public boolean validate(JWT jwt) {
            Object claimValue = jwt.getClaim(claimToValidate);
            if(claimValue == null) {
                setErrorMessage(claimToValidate + " claim is not present");
                return false;
            }
            if(!validator.apply(claimValue)) {
                setErrorMessage(errorMessage);
                return false;
            }
            return true;
        }
    }

    public JWTValidatorBuilder clone() throws CloneNotSupportedException {
        JWTValidatorBuilder clone = (JWTValidatorBuilder) super.clone();
        JWTValidatorBuilder newBuilder = new JWTValidatorBuilder();
        newBuilder.validator.addToValidators(this.validator);
        return newBuilder;
    }

    private static class PresenceValidator extends AbstractJWTValidator {
        private final String claim;
        private final boolean requirePresence;

        PresenceValidator(String claim, boolean requirePresence) {
            this.claim = claim;
            this.requirePresence = requirePresence;
        }

        @Override
        public boolean validate(JWT jwt) {
            Object claimValue = jwt.getClaim(claim);
            if(claimValue == null) {
                if(requirePresence) {
                    setErrorMessage(claim + " claim not present");
                    return false;
                }
                return true;
            }
            if(!requirePresence) {
                setErrorMessage(claim + " claim is present");
                return false;
            }
            return true;
        }
    }
}
