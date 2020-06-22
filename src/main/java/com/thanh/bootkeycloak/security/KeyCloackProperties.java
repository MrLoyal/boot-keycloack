package com.thanh.bootkeycloak.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "keycloack")
public class KeyCloackProperties {
    private String serviceUri = "http://localhost:8080";

    public String getServiceUri() {
        return serviceUri;
    }

    public void setServiceUri(String serviceUri) {
        this.serviceUri = serviceUri;
    }
}
