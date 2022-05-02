package am.ysu.security.paseto;

import am.ysu.security.paseto.structure.Version;
import am.ysu.security.paseto.utils.protocol.V1ProtocolImplementor;
import am.ysu.security.paseto.utils.protocol.V2ProtocolImplementor;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public interface ProtocolSpecImplementor
{
    /**
     @see  <a href="https://tools.ietf.org/id/draft-paragon-paseto-rfc-00.html#base64-encoding">Paseto token encoding format</a>
     */
    Base64.Decoder B64_DECODER = Base64.getUrlDecoder();
    Base64.Encoder B64_ENCODER = Base64.getUrlEncoder().withoutPadding();

    static ProtocolSpecImplementor selectImplementor(Version version) {
        return switch (version) {
            case v1 -> V1ProtocolImplementor.getInstance();
            case v2 -> V2ProtocolImplementor.getInstance();
            default -> throw new IllegalArgumentException("Unsupported PASETO protocol version " + version);
        };
    }

    String encrypt(byte[] key, byte[] message, byte[] footer);

    String decrypt(byte[] key, String token);

    String sign(PrivateKey privateKey, byte[] message, byte[] footer);

    String verify(PublicKey publicKey, String token);

    default String encrypt(byte[] key, byte[] message) {
        return encrypt(key, message, new byte[0]);
    }

    default String encrypt(byte[] key, String message) {
        return encrypt(key, message.getBytes(StandardCharsets.UTF_8), new byte[0]);
    }

    default String encrypt(byte[] key, byte[] message, String footer) {
        return encrypt(key, message, footer.getBytes(StandardCharsets.UTF_8));
    }

    default String encrypt(byte[] key, String message, String footer) {
        return encrypt(key, message.getBytes(StandardCharsets.UTF_8), footer.getBytes(StandardCharsets.UTF_8));
    }

    default String encrypt(byte[] key, String message, byte[] footer) {
        return encrypt(key, message.getBytes(StandardCharsets.UTF_8), footer);
    }

    default String sign(PrivateKey key, byte[] message) {
        return sign(key, message, new byte[0]);
    }

    default String sign(PrivateKey key, String message) {
        return sign(key, message.getBytes(StandardCharsets.UTF_8), new byte[0]);
    }

    default String sign(PrivateKey key, byte[] message, String footer) {
        return sign(key, message, footer.getBytes(StandardCharsets.UTF_8));
    }

    default String sign(PrivateKey key, String message, String footer) {
        return sign(key, message.getBytes(StandardCharsets.UTF_8), footer.getBytes(StandardCharsets.UTF_8));
    }

    default String sign(PrivateKey key, String message, byte[] footer) {
        return sign(key, message.getBytes(StandardCharsets.UTF_8), footer);
    }

}
