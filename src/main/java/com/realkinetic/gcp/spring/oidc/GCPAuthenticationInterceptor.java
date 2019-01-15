package com.realkinetic.gcp.spring.oidc;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;

/**
 * <p>A {@link org.springframework.web.client.RestTemplate} interceptor which can make HTTP requests to Google
 * OIDC-authenticated resources using a service account. For example, this can be used to make requests to resources
 * behind an Identity-Aware Proxy (https://cloud.google.com/iap).</p>
 * <p>
 * <p>This works by generating a JWT with an additional {@code target_audience} claim set to the OAuth2 client id which
 * is signed using the GCP service account credentials. This JWT is then exchanged for a Google-signed OIDC token for
 * the client id specified in the JWT claims. Authenticated requests are made by setting the token in the
 * {@code Authorization: Bearer} header. This token has roughly a 1-hour expiration and is renewed transparently by the
 * interceptor.</p>
 */
public class GCPAuthenticationInterceptor implements ClientHttpRequestInterceptor {

    private static final String IAM_SCOPE = "https://www.googleapis.com/auth/iam";
    private static final String OAUTH_TOKEN_URI = "https://www.googleapis.com/oauth2/v4/token";
    private static final String JWT_BEARER_TOKEN_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final long EXPIRATION_TIME_IN_MILLIS = 3600 * 1000L;
    private static final HttpTransport httpTransport = new NetHttpTransport();

    private final String clientId;
    private final ServiceAccountCredentials credentials;
    private DecodedJWT googleJwt;

    /**
     * Create a new interceptor which authenticates HTTP requests for the given OAuth2 client id.
     *
     * @param clientId GCP OAuth2 client id
     * @throws IOException if GCP service account credentials cannot be loaded
     */
    public GCPAuthenticationInterceptor(String clientId) throws IOException {
        this.clientId = clientId;
        this.credentials = getCredentials();
    }

    @Override
    @NonNull
    public ClientHttpResponse intercept(
            @NonNull org.springframework.http.HttpRequest request,
            @NonNull byte[] body,
            @NonNull ClientHttpRequestExecution execution) throws IOException {

        synchronized (this) {
            if (googleJwt == null || googleJwt.getExpiresAt().before(new Date())) {
                googleJwt = getGoogleIdToken();
            }
            request.getHeaders().add("Authorization", "Bearer " + googleJwt.getToken());
        }
        return execution.execute(request, body);
    }

    private DecodedJWT getGoogleIdToken() throws IOException {
        String jwt = getSignedJwt();
        final GenericData tokenRequest = new GenericData()
                .set("grant_type", JWT_BEARER_TOKEN_GRANT_TYPE)
                .set("assertion", jwt);
        final UrlEncodedContent content = new UrlEncodedContent(tokenRequest);

        final HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

        final HttpRequest request = requestFactory
                .buildPostRequest(new GenericUrl(OAUTH_TOKEN_URI), content)
                .setParser(new JsonObjectParser(JacksonFactory.getDefaultInstance()));

        HttpResponse response = request.execute();
        GenericData responseData = response.parseAs(GenericData.class);
        String idToken = (String) responseData.get("id_token");
        return JWT.decode(idToken);
    }

    private ServiceAccountCredentials getCredentials() throws IOException {
        GoogleCredentials credentials = GoogleCredentials
                .getApplicationDefault()
                .createScoped(Collections.singleton(IAM_SCOPE));

        // Service account credentials are required to sign the jwt token.
        if (credentials == null || !(credentials instanceof ServiceAccountCredentials)) {
            throw new RuntimeException("Google credentials : service accounts credentials expected");
        }
        return (ServiceAccountCredentials) credentials;
    }

    private String getSignedJwt() {
        long now = System.currentTimeMillis();
        RSAPrivateKey privateKey = (RSAPrivateKey) credentials.getPrivateKey();
        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        return JWT.create()
                .withKeyId(credentials.getPrivateKeyId())
                .withIssuer(credentials.getClientEmail())
                .withSubject(credentials.getClientEmail())
                .withAudience(OAUTH_TOKEN_URI)
                .withIssuedAt(new Date(now))
                .withExpiresAt(new Date(now + EXPIRATION_TIME_IN_MILLIS))
                .withClaim("target_audience", clientId)
                .sign(algorithm);
    }
}