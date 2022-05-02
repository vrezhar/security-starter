package am.ysu.security.paseto.tokens;

import am.ysu.security.paseto.ProtocolSpecImplementor;
import am.ysu.security.paseto.structure.Purpose;
import am.ysu.security.paseto.structure.Version;
import am.ysu.security.paseto.utils.Helper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class PasetoToken <Message, Footer> {
    private static final ObjectMapper MAPPER = Helper.createObjectMapper();

    private final Version version;
    private final Purpose purpose;
    private final Message message;
    private final Footer footer;

    public PasetoToken(Version version, Purpose purpose, Message message, Footer footer) {
        this.version = version;
        this.purpose = purpose;
        this.message = message;
        this.footer = footer;
    }

    public PasetoToken(Version version, Purpose purpose, Message message) {
        this(version, purpose, message, null);
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

    public Message getMessage() {
        return message;
    }

    public Footer getFooter() {
        return footer;
    }

    public String encrypt(byte[] key) throws JsonProcessingException {
        if(purpose == Purpose.PUBLIC) {
            throw new UnsupportedOperationException("Cannot encrypt public PASETO tokens");
        }
        if(footer == null) {
            return ProtocolSpecImplementor.selectImplementor(version).encrypt(key, MAPPER.writeValueAsBytes(message));
        }
        return ProtocolSpecImplementor.selectImplementor(version).encrypt(key, MAPPER.writeValueAsBytes(message), MAPPER.writeValueAsBytes(footer));
    }

    public String sign(PrivateKey privateKey) throws JsonProcessingException {
        if(purpose == Purpose.LOCAL) {
            throw new UnsupportedOperationException("Cannot sign local PASETO tokens");
        }
        if(footer == null) {
            return ProtocolSpecImplementor.selectImplementor(version).sign(privateKey, MAPPER.writeValueAsBytes(message));
        }
        return ProtocolSpecImplementor.selectImplementor(version).sign(privateKey, MAPPER.writeValueAsBytes(message), MAPPER.writeValueAsBytes(footer));
    }

    public static <M, F> PasetoToken<M, F> parseToken(String token, byte[] key, Class<M> messageType, Class<F> footerType) throws IOException {
        final String[] parts = checkStructure(token);
        final Version version = Version.valueOf(parts[0]);
        final Purpose purpose = Purpose.of(parts[1]);
        if(purpose != Purpose.LOCAL) {
            throw new IllegalArgumentException("PASETO token is not encrypted");
        }
        final ProtocolSpecImplementor specImplementor = ProtocolSpecImplementor.selectImplementor(version);
        if(parts.length == 4) {
            final byte[] footer = Base64.getUrlDecoder().decode(parts[3]);
            return new PasetoToken<>(
                    version, purpose,
                    MAPPER.readValue(specImplementor.decrypt(key, token), messageType),
                    MAPPER.readValue(footer, footerType)
            );
        }
        return new PasetoToken<>(version, purpose, MAPPER.readValue(specImplementor.decrypt(key, token), messageType));
    }

    public static <M> PasetoToken<M, String> parseToken(String token, byte[] key, Class<M> messageType) throws IOException {
        return parseToken(token, key, messageType, String.class);
    }

    public static <M, F> PasetoToken<M, F> parseToken(String token, PublicKey key, Class<M> messageType, Class<F> footerType) throws IOException {
        final String[] parts = checkStructure(token);
        final Version version = Version.valueOf(parts[0]);
        final Purpose purpose = Purpose.of(parts[1]);
        if(purpose != Purpose.PUBLIC) {
            throw new IllegalArgumentException("PASETO token is not signed");
        }
        final ProtocolSpecImplementor specImplementor = ProtocolSpecImplementor.selectImplementor(version);
        if(parts.length == 4) {
            return new PasetoToken<>(
                    version, purpose,
                    MAPPER.readValue(specImplementor.verify(key, token), messageType),
                    MAPPER.readValue(Base64.getUrlDecoder().decode(parts[3]), footerType)
            );
        }
        return new PasetoToken<>(version, purpose, MAPPER.readValue(specImplementor.verify(key, token), messageType));
    }

    public static <M> PasetoToken<M, String> parseToken(String token, PublicKey key, Class<M> messageType) throws IOException {
        return parseToken(token, key, messageType, String.class);
    }

    private static String[] checkStructure(String token) {
        final String[] parts = token.split("\\.");
        if (parts.length < 3 || parts.length > 5) {
            throw new IllegalArgumentException("Invalid PASETO format for token " + token);
        }
        return parts;
    }
}
