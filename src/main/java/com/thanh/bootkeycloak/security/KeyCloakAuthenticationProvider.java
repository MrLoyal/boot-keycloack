package com.thanh.bootkeycloak.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class KeyCloakAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(KeyCloakAuthenticationProvider.class);

    private KeyCloakProperties keyCloakProperties;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        CloseableHttpClient client = HttpClients.createDefault();

        String tokenUri = keyCloakProperties.getServiceUri()
                + "/realms/{REALM_NAME}/protocol/openid-connect/token"
                .replace("{REALM_NAME}", keyCloakProperties.getRealmName());
        HttpPost post = new HttpPost(tokenUri);

        String clientId = keyCloakProperties.getClientId();
        String clientSecret = keyCloakProperties.getClientSecret();
        String authorization = Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        post.setHeader("Authorization", "Basic " + authorization);


        String username = token.getPrincipal().toString();
        String password = token.getCredentials().toString();
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("username", username));
        params.add(new BasicNameValuePair("password", password));
        try {
            UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params);
            post.setEntity(entity);
            CloseableHttpResponse httpResponse = client.execute(post);
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode == 200) {
                return success(httpResponse, username);
            } else if (statusCode == 401 || statusCode == 400) {
                // {"error":"invalid_grant","error_description":"Invalid user credentials"}
                String bodyStr = EntityUtils.toString(httpResponse.getEntity());
                ObjectMapper mapper = new ObjectMapper();
                JsonNode responseNode = mapper.readTree(bodyStr);
                JsonNode errorNode = responseNode.get("error");
                JsonNode errorDescNode = responseNode.get("error_description");
                if (errorNode != null && errorDescNode != null
                        && "invalid_grant".equals(errorNode.asText())) {
                    if ("Invalid user credentials".equals(errorDescNode.asText())) {
                        throw new BadCredentialsException("Invalid user credentials");
                    } else if ("Account disabled".equals(errorDescNode.asText())) {
                        throw new DisabledException("Account disabled");
                    }
                } else {
                    logger.debug("Status code ============== {}", statusCode);
                    logger.debug("Unsuccessfully authenticated: {}", bodyStr);
                }

            } else {
                logger.debug("Status code ============== {}", statusCode);
                logger.debug("Unsuccessfully authenticated: {}", EntityUtils.toString(httpResponse.getEntity()));
            }
            throw new InternalAuthenticationServiceException("Unknown error");
        } catch (HttpHostConnectException e) {
            logger.error("Could not connect to KeyCloak", e);
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        } catch (IOException e) {
            logger.error("", e);
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }
    }

    private Authentication success(CloseableHttpResponse httpResponse, String username) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode responseNode = mapper.readTree(httpResponse.getEntity().getContent());
        KeyCloakAuthenticationToken auth = new KeyCloakAuthenticationToken(username, "[HiddenPassword]");
        auth.setAuthenticated(true);
        auth.setAccessToken(responseNode.get("access_token").asText());
        auth.setRefreshToken(responseNode.get("refresh_token").asText());
        auth.setExpiresIn(responseNode.get("expires_in").asLong());
        auth.setRefreshExpiresIn(responseNode.get("refresh_expires_in").asLong());
        auth.setTokenType(responseNode.get("token_type").asText());
        auth.setScope(responseNode.get("scope").asText());

        return auth;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return UsernamePasswordAuthenticationToken.class == clazz;
    }

    public void setKeyCloakProperties(KeyCloakProperties keyCloakProperties) {
        this.keyCloakProperties = keyCloakProperties;
    }
}
