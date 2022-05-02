package am.ysu.security.security.util.signature;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class CertificateHelper {
    private CertificateHelper(){}

    public static X509Certificate getX509Certificate(String x509Certificate) throws CertificateException {
        return (X509Certificate)getCertificate(x509Certificate, "X.509");
    }

    public static Certificate getCertificate(String cert, String type) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(type);
        String pureCertEncoded = cert
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "");
        ByteArrayInputStream certInStream = new ByteArrayInputStream(Base64.getDecoder().decode(pureCertEncoded.getBytes(StandardCharsets.UTF_8)));
        return certificateFactory.generateCertificate(certInStream);
    }

    public static boolean isCertificateValid(X509Certificate certificate) {
        Date now = new Date();
        Date notAfter = certificate.getNotAfter();
        if(notAfter == null){
            return false;
        }
        boolean expired = now.after(notAfter);
        Date notBefore = certificate.getNotBefore();
        if(notBefore != null){
            return now.after(notBefore) && !expired;
        }
        return !expired;
    }

    public static boolean isCertificateTrusted(X509Certificate certificate, List<X509Certificate> trustedCerts) {
        for (X509Certificate trustedCACertificate : trustedCerts) {
            try {
                certificate.verify(trustedCACertificate.getPublicKey());
                return true;
            } catch (GeneralSecurityException ignored) { }
        }
        return false;
    }
}
