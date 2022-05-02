package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.alg.AlgorithmDefinition;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import java.util.Collections;
import java.util.List;

public class AlgorithmValidator extends AbstractJWTValidator {
    private final List<AlgorithmDefinition> supportedAlgorithms;

    public AlgorithmValidator(AlgorithmDefinition definition) {
        this.supportedAlgorithms = Collections.singletonList(definition);
    }

    public AlgorithmValidator(List<AlgorithmDefinition> supportedAlgorithms) {
        this.supportedAlgorithms = supportedAlgorithms;
    }

    public AlgorithmValidator(AlgorithmDefinition... definitions) {
        this.supportedAlgorithms = List.of(definitions);
    }

    @Override
    public boolean validate(JWT jwt) {
        final var alg = AlgorithmDefinition.extractDefinition(jwt);
        if(alg == null) {
            setErrorMessage("Invalid JWT");
            return false;
        }
        if(!supportedAlgorithms.contains(alg)) {
            setErrorMessage("Invalid Algorithm");
            return false;
        }
        return true;
    }
}
