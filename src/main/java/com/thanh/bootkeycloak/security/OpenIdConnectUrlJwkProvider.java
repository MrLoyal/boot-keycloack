package com.thanh.bootkeycloak.security;

import com.auth0.jwk.UrlJwkProvider;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class OpenIdConnectUrlJwkProvider extends UrlJwkProvider {

    private static final String CERT_PATH = "/realms/{REAM_NAME}/protocol/openid-connect/certs";
    private static KeyCloakProperties keyCloakProperties;

    public OpenIdConnectUrlJwkProvider(String domain) {
        this(urlForDomain(domain));
    }

    public OpenIdConnectUrlJwkProvider(URL url) {
        super(url);
    }

    private static URL urlForDomain(String domain) {
        if (!domain.startsWith("http")) {
            domain = "https://" + domain;
        }

        try {
            final URI uri
                    = new URI(domain + CERT_PATH.replace("{REAM_NAME}", keyCloakProperties.getRealmName()))
                    .normalize();
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("Invalid jwks uri", e);
        }
    }

    public static synchronized void setKeyCloakProperties(KeyCloakProperties _keyCloakProperties) {
        keyCloakProperties = _keyCloakProperties;
    }
}
