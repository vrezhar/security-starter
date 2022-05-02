package am.ysu.security.paseto.tokens;

import am.ysu.security.paseto.ProtocolSpecImplementor;
import am.ysu.security.paseto.structure.Purpose;
import am.ysu.security.paseto.structure.Version;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class DefaultPasetoToken {
    private final Version version;
    private final Purpose purpose;
    private final String payload;
    private final String footer;

    public DefaultPasetoToken(Version version, Purpose purpose, String payload, String footer) {
        this.version = version;
        this.purpose = purpose;
        this.payload = payload;
        this.footer = footer;
    }

    public DefaultPasetoToken(Version version, Purpose purpose, String payload) {
        this.version = version;
        this.purpose = purpose;
        this.payload = payload;
        this.footer = "";
    }

    public DefaultPasetoToken(String token) {
        final String[] parts = token.split("\\.");
        if(parts.length < 3 || parts.length > 4) {
            throw new IllegalArgumentException("Invalid PASETO token");
        }
        this.version = Version.valueOf(parts[0]);
        this.purpose = Purpose.of(parts[1]);
        this.payload = parts[2];
        if(parts.length == 3) {
            this.footer = "";
        } else {
            this.footer = parts[3];
        }
    }

    public DefaultPasetoToken(Version version, byte[] message, byte[] footer, byte[] key) {
        this(ProtocolSpecImplementor.selectImplementor(version).encrypt(key, message, footer));
    }

    public DefaultPasetoToken(Version version, String message, String footer, byte[] key) {
        this(ProtocolSpecImplementor.selectImplementor(version).encrypt(key, message, footer));
    }

    public DefaultPasetoToken(Version version, byte[] message, byte[] key) {
        this(ProtocolSpecImplementor.selectImplementor(version).encrypt(key, message));
    }

    public DefaultPasetoToken(Version version, String message, byte[] key) {
        this(ProtocolSpecImplementor.selectImplementor(version).encrypt(key, message));
    }

    public DefaultPasetoToken(Version version, byte[] message, byte[] footer, PrivateKey privateKey) {
        this(ProtocolSpecImplementor.selectImplementor(version).sign(privateKey, message, footer));
    }

    public DefaultPasetoToken(Version version, String message, String footer, PrivateKey privateKey) {
        this(ProtocolSpecImplementor.selectImplementor(version).sign(privateKey, message, footer));
    }

    public String getHeader() {
        return version + "." + purpose;
    }

    public Version getVersion() {
        return version;
    }

    public Purpose getPurpose() {
        return purpose;
    }

    public String getRawPayload() {
        return payload;
    }

    public String getRawFooter() {
        return new String(Base64.getUrlDecoder().decode(footer), StandardCharsets.UTF_8);
    }

    public String getTokenEncoded() {
        final StringBuilder sb = new StringBuilder();
        sb.append(version.name()).append(".");
        sb.append(purpose.name()).append(".");
        sb.append(payload);
        if(footer != null) {
            sb.append(".").append(footer);
        }
        return sb.toString();
    }

    public String verify(PublicKey publicKey) {
        return ProtocolSpecImplementor.selectImplementor(version).verify(publicKey, getTokenEncoded());
    }

    public String decrypt(byte[] key) {
        return ProtocolSpecImplementor.selectImplementor(version).decrypt(key, getTokenEncoded());
    }

    public String decrypt(String key) {
        return ProtocolSpecImplementor.selectImplementor(version).decrypt(key.getBytes(StandardCharsets.ISO_8859_1), getTokenEncoded());
    }
}
