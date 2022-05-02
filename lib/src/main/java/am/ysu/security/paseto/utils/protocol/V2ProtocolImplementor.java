package am.ysu.security.paseto.utils.protocol;

import am.ysu.security.paseto.ProtocolSpecImplementor;
import am.ysu.security.paseto.utils.Constants;
import am.ysu.security.paseto.utils.Helper;
import am.ysu.security.paseto.utils.error.AuthenticationException;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

public class V2ProtocolImplementor implements ProtocolSpecImplementor {
    private static final V2ProtocolImplementor INSTANCE = new V2ProtocolImplementor();

    public static V2ProtocolImplementor getInstance() {
        return INSTANCE;
    }

    private V2ProtocolImplementor() { }

    @Override
    public String encrypt(byte[] key, byte[] message, byte[] footer) {
        throw new UnsupportedOperationException("PASETO v2 encryption is not supported");
    }

    @Override
    public String decrypt(byte[] key, String token) {
        throw new UnsupportedOperationException("PASETO v2 decryption is not supported");
    }

    @Override
    public String sign(PrivateKey privateKey, byte[] message, byte[] footer) {
        final byte[] m2 = Helper.PAE(Constants.V2.PUBLIC_HEADER.getBytes(StandardCharsets.UTF_8), message, footer);
        final byte[] signature;
        try {
            signature = Helper.V2.signEd25519(privateKey, m2);
        } catch (InvalidKeyException | SignatureException e) {
            throw new RuntimeException("PASETO v2.Sign operation failed due to unexpected " + e.getClass().getSimpleName() + " exception", e);
        }
        if(footer.length == 0) {
            return Constants.V2.PUBLIC_HEADER + B64_ENCODER.encodeToString(Helper.concatenate(message, signature));
        }
        return Constants.V2.PUBLIC_HEADER + B64_ENCODER.encodeToString(Helper.concatenate(message, signature)) + "." + B64_ENCODER.encodeToString(footer);
    }

    @Override
    public String verify(PublicKey publicKey, String token) {
        if(!token.startsWith(Constants.V2.PUBLIC_HEADER)) {
            throw new IllegalArgumentException("Passed token " + token + " is not a valid PASETO v2 public token");
        }
        final String[] parts = token.split("\\.");
        final byte[] payload = B64_DECODER.decode(parts[2]);
        final byte[] f;
        if(parts.length == 4) {
            f = B64_DECODER.decode(parts[3]);
        } else {
            f = new byte[0];
        }
        if(payload.length <= 64) {
            throw new IllegalArgumentException("Provided token " + token + " doesn't contain a valid payload for a PASETO v2 public token");
        }
        final byte[] s = Arrays.copyOfRange(payload, payload.length - 64, payload.length);
        final byte[] m = Arrays.copyOf(payload, payload.length - 64);
        final byte[] m2 = Helper.PAE(Constants.V2.PUBLIC_HEADER.getBytes(StandardCharsets.UTF_8), m, f);
        try {
            if(Helper.V2.verifyEd25519(publicKey, m2, s)) {
                return new String(m, StandardCharsets.UTF_8);
            }
            throw new AuthenticationException("Signature verification failed");
        } catch (InvalidKeyException | SignatureException e) {
            throw new AuthenticationException("Signature verification failed due to an exception of type " + e.getClass().getSimpleName(), e);
        }
    }
}
