package am.ysu.security.jwt.validators.common;

import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.AbstractJWTValidator;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;

public class RemoteTokenValidator extends AbstractJWTValidator
{
    private final String authenticationServerUrl;

    public RemoteTokenValidator(String authenticationServerUrl) {
        this.authenticationServerUrl = authenticationServerUrl;
    }

    @Override
    public boolean validate(JWT jwt) {
        try {
            URL url = new URL(authenticationServerUrl);
            HttpsURLConnection connection = (HttpsURLConnection)url.openConnection();
            connection.setRequestProperty("Authorization", "Bearer " + jwt.getJWTEncoded());
            int responseCode = connection.getResponseCode();
            if(responseCode >= 300 || responseCode < 200){
                setErrorMessage("Remote validation failed, Http response code is " + responseCode);
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
