# gcp-spring-oidc

This contains a Spring `RestTemplate` interceptor which can make HTTP requests to Google
OIDC-authenticated resources using a service account. For example, this can be used to
make requests to resources behind an [Identity-Aware Proxy (IAP)](https://cloud.google.com/iap).

This works by generating a JWT with an additional `target_audience` claim set to the
OAuth2 client id which is signed using the GCP service account credentials. This JWT is
then exchanged for a Google-signed OIDC token for the client id specified in the JWT
claims. Authenticated requests are made by setting the token in the `Authorization: Bearer`
header. This token has roughly a 1-hour expiration and is renewed transparently by the
interceptor.

More information on the implementation flow can be found in the
[GCP documentation](https://cloud.google.com/iap/docs/authentication-howto) for IAP.

## Usage

It is recommended to use a singleton instance of `GCPAuthenticationInterceptor` since it
will cache the OIDC token used for authentication and only renew once the token has
expired.

```java
private static final String CLIENT_ID = "<GCP OAuth2 Client ID>.apps.googleusercontent.com";
private RestTemplate restTemplate;

private synchronized RestTemplate restTemplate() throws IOException {
    if (restTemplate != null) {
        return restTemplate;
    }
    restTemplate = new RestTemplate();
    List<ClientHttpRequestInterceptor> interceptors = restTemplate.getInterceptors();
    if (CollectionUtils.isEmpty(interceptors)) {
        interceptors = new ArrayList<>();
    }
    interceptors.add(new GCPAuthenticationInterceptor(CLIENT_ID));
    restTemplate.setInterceptors(interceptors);
    return restTemplate;
}
```
