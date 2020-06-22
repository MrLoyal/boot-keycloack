package com.thanh.bootkeycloak;

import com.thanh.bootkeycloak.security.KeyCloakProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {KeyCloakProperties.class})
public class BootKeycloakApplication {

    public static void main(String[] args) {
        SpringApplication.run(BootKeycloakApplication.class, args);
    }

}
