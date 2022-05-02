package am.ysu.security.paseto.util;

import java.security.Provider;
import java.security.Security;

public class TestingRngProvider extends Provider {

    public TestingRngProvider() {
        this("TestingRngProvider", "1.0.0", "Noop RNG implementor");
        put("SecureRandom.NOOP", "com.estate.paseto.util.NoopSecureRandomProvider");
        put("SecureRandom.V2S1", "com.estate.paseto.util.v2.V2Provider");
        put("SecureRandom.V2S2", "com.estate.paseto.util.v2.V2Provider");
        Security.setProperty("securerandom.strongAlgorithms", "NOOP");
    }

    protected TestingRngProvider(String name, double version, String info) {
        super(name, version, info);
    }

    protected TestingRngProvider(String name, String versionStr, String info) {
        super(name, versionStr, info);
    }
}
