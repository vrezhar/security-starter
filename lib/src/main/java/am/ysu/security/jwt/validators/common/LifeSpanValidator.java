package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class LifeSpanValidator extends AbstractJWTValidator {
    private final Date lowerLimit;
    private final Date upperLimit;

    public LifeSpanValidator(Date issuedNotSoonerThan, Date notExpiredBefore) {
        super();
        this.lowerLimit = issuedNotSoonerThan;
        this.upperLimit = notExpiredBefore;
    }

    public LifeSpanValidator(Date issuedNotSoonerThan) {
        this(issuedNotSoonerThan, new Date());
    }

    public LifeSpanValidator() {
        this(Date.from(Instant.EPOCH), new Date());
    }

    @Override
    public boolean validate(JWT jwt) {
        try {
            Date iat = jwt.getIssuedDate();
            if(iat == null) {
                setErrorMessage("Issued date claim not present");
                return false;
            }
            if(iat.before(lowerLimit)) {
                setErrorMessage("Token issued before acceptable date " + DateTimeFormatter.ISO_DATE_TIME.format(lowerLimit.toInstant()));
                return false;
            }
            Date exp = jwt.getExpirationDate();
            if(exp == null) {
                setErrorMessage("Expiration date claim not present");
                return false;
            }
            if(exp.before(upperLimit)) {
                setErrorMessage("Token has expired");
                return false;
            }
            return true;
        }
        catch (Exception e) {
            setErrorMessage(e.getMessage());
            return false;
        }
    }
}
