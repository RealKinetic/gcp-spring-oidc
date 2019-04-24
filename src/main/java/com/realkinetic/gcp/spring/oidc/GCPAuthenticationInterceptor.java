package com.realkinetic.gcp.spring.oidc;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.jose4j.base64url.Base64;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.util.Collections;

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
    private static final float EXPIRATION_TIME_IN_MINS = 60;
    private static final HttpTransport httpTransport = new NetHttpTransport();

    private final String clientId;
    private final GoogleCredentials credentials;
    private JwtContext googleJwt;

    /**
     * Create a new interceptor which authenticates HTTP requests for the given OAuth2 client id.
     *
     * @param clientId GCP OAuth2 client id
     * @throws IOException if GCP service account credentials cannot be loaded
     */
    public GCPAuthenticationInterceptor(String clientId) throws IOException {
        this.clientId = clientId;
        this.credentials = GoogleCredentials
                .getApplicationDefault()
                .createScoped(Collections.singleton(IAM_SCOPE));
    }

    @Override
    @NonNull
    public ClientHttpResponse intercept(
            @NonNull org.springframework.http.HttpRequest request,
            @NonNull byte[] body,
            @NonNull ClientHttpRequestExecution execution) throws IOException {

        synchronized (this) {
            if (googleJwt == null || isExpired()) {
                googleJwt = getGoogleIdToken();
            }
            request.getHeaders().add("Authorization", "Bearer " + googleJwt.getJwt());
        }
        return execution.execute(request, body);
    }

    private JwtContext getGoogleIdToken() throws IOException {
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
        return decode(idToken);
    }

    private boolean isExpired() {
        try {
            return googleJwt.getJwtClaims().getExpirationTime().isBefore(NumericDate.now());
        } catch (MalformedClaimException e) {
            return true;
        }
    }

    private JwtContext decode(String jwt) throws IOException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience(clientId)
                .setSkipSignatureVerification()
                .build();
        try {
            return jwtConsumer.process(jwt);
        } catch (InvalidJwtException e) {
            throw new IOException(e);
        }
    }

    private String getSignedJwt() throws IOException {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(OAUTH_TOKEN_URI);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(EXPIRATION_TIME_IN_MINS);
        claims.setClaim("target_audience", clientId);

        String jwt;
        if (credentials instanceof ServiceAccountCredentials) {
            // ServiceAccountCredentials indicates credentials provided through GOOGLE_APPLICATION_CREDENTIALS, which
            // means we have the key to sign the JWT ourselves.
            ServiceAccountCredentials creds = (ServiceAccountCredentials) credentials;
            claims.setIssuer(creds.getClientEmail());
            claims.setSubject(creds.getClientEmail());
            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(creds.getPrivateKey());
            jws.setKeyIdHeaderValue(creds.getPrivateKeyId());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            try {
                jwt = jws.getCompactSerialization();
            } catch (JoseException e) {
                throw new IOException(e);
            }
        } else if (credentials instanceof ComputeEngineCredentials) {
            // ComputeEngineCredentials indicates we're running in a managed environment (e.g. GCE or App Engine), which
            // means we do not have the key to sign the JWT ourselves. Use the IAM signBlob API to sign it instead.
            ComputeEngineCredentials creds = (ComputeEngineCredentials) credentials;
            claims.setIssuer(creds.getAccount());
            claims.setSubject(creds.getAccount());
            String claimsJson = claims.toJson();
            JwtClaims headers = new JwtClaims();
            headers.setClaim("typ", "JWT");
            headers.setClaim("alg", AlgorithmIdentifiers.RSA_USING_SHA256);
            String headersJson = headers.toJson();
            // JWT consists of "<b64(headers)>.<b64(claims)>".
            String payload = Base64.encode(headersJson.getBytes()) + "." + Base64.encode(claimsJson.getBytes());
            byte[] signature = creds.sign(payload.getBytes());
            // Signed JWT consists of "<b64(headers)>.<b64(claims)>.<b64(signature)>".
            jwt = payload + "." + Base64.encode(signature);
        } else {
            throw new RuntimeException("Google credentials: service accounts credentials expected");
        }
        return jwt;
    }
}