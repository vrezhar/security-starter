package am.ysu.security.jwk;

public interface JWK {
    String getKeyType();

    String getUsage();

    String getAlgorithm();

    String getKeyId();
}
