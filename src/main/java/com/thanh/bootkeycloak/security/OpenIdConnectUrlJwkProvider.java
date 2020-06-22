package com.thanh.bootkeycloak.security;

import com.auth0.jwk.UrlJwkProvider;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class OpenIdConnectUrlJwkProvider extends UrlJwkProvider {

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
            final URI uri = new URI(domain + "/realms/realm1/protocol/openid-connect/certs").normalize();
            return uri.toURL();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("Invalid jwks uri", e);
        }
    }
}
