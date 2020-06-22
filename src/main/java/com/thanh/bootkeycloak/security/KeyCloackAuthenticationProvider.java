package com.thanh.bootkeycloak.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class KeyCloackAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(KeyCloackAuthenticationProvider.class);

    private KeyCloackProperties keyCloackProperties;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        CloseableHttpClient client = HttpClients.createDefault();

        HttpPost post = new HttpPost("http://localhost:8080/auth/realms/realm1/protocol/openid-connect/token");

        String clientId = "client1";
        String clientSecret = "303c3a48-1449-495f-a1b7-496537851e65";
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
                ObjectMapper mapper = new ObjectMapper();
                JsonNode responseNode = mapper.readTree(httpResponse.getEntity().getContent());
                KeyCloackAuthenticationToken auth = new KeyCloackAuthenticationToken(username, password);
                auth.setAuthenticated(true);
                auth.setAccessToken(responseNode.get("access_token").asText());

                return auth;
            } else {
                logger.debug("Unsuccessfully authenticated: {}", EntityUtils.toString(httpResponse.getEntity()));
                logger.debug("Status code = {}", statusCode);
                throw new BadCredentialsException("Lala");
            }
        } catch (Exception e) {
            logger.error("", e);
            throw new InternalAuthenticationServiceException(e.getMessage());
        }
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return UsernamePasswordAuthenticationToken.class == clazz;
    }

    public void setKeyCloackProperties(KeyCloackProperties keyCloackProperties) {
        this.keyCloackProperties = keyCloackProperties;
    }
}
