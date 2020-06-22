package com.thanh.bootkeycloak.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.thanh.bootkeycloak.util.Constants;
import org.apache.http.conn.HttpHostConnectException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(LoginFilter.class);
    private MessageSource messageSource;

    protected LoginFilter() {
        super(Constants.LOGIN_URL);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        logger.debug("Attempting authentication for a request that matches {}", Constants.LOGIN_URL);
        LoginRequest loginRequest = getLoginRequest(request);
        if (loginRequest != null) {
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
            return getAuthenticationManager().authenticate(token);
        } else {
            throw new BadCredentialsException("Login request is null");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        if (authResult instanceof KeyCloakAuthenticationToken) {
            KeyCloakAuthenticationToken token = (KeyCloakAuthenticationToken) authResult;
            ObjectMapper mapper = new ObjectMapper();

            LoginSuccessResponse loginSuccessResponse = new LoginSuccessResponse();
            loginSuccessResponse.setAccessToken(token.getAccessToken());
            loginSuccessResponse.setRefreshToken(token.getRefreshToken());
            loginSuccessResponse.setExpiresIn(token.getExpiresIn());
            loginSuccessResponse.setRefreshTokenExpiresIn(token.getRefreshExpiresIn());
            loginSuccessResponse.setTokenType(token.getTokenType());
            loginSuccessResponse.setScope(token.getScope());

            String str = mapper.writeValueAsString(loginSuccessResponse);

            response.setStatus(200);
            SecUtil.writeCorsHeaders(request, response);
            response.addHeader("Content-Type", "application/json; charset=utf-8");
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(response.getOutputStream(), StandardCharsets.UTF_8));
            writer.write(str);
            writer.flush();
            writer.close();
        } else {
            logger.warn("authResult is not of type KeyCloakAuthenticationToken");
        }
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        if (failed instanceof InternalAuthenticationServiceException) {
            response.setStatus(500);
            node.put("code", "INTERNAL_SERVER_ERROR");
            InternalAuthenticationServiceException myFailed = (InternalAuthenticationServiceException) failed;
            Throwable cause = myFailed.getCause();
            if (cause instanceof HttpHostConnectException) {
                String msg = messageSource.getMessage("couldNotConnectToAccountServer", null, LocaleContextHolder.getLocale());
                node.put("message", msg);
            } else {
                String msg = messageSource.getMessage("internalServerError", null, LocaleContextHolder.getLocale());
                node.put("message", msg);
            }
        } else if (failed instanceof DisabledException) {
            response.setStatus(401);
            node.put("code", "ACCOUNT_DISABLED");
            String msg = messageSource.getMessage("accountDisabled", null, LocaleContextHolder.getLocale());
            node.put("message", msg);
        } else if (failed instanceof BadCredentialsException) {
            response.setStatus(401);
            node.put("code", "BAD_CREDENTIALS");
            String msg = messageSource.getMessage("badCredentials", null, LocaleContextHolder.getLocale());
            node.put("message", msg);
        } else {
            // Default
            response.setStatus(500);
            node.put("code", "INTERNAL_SERVER_ERROR");
            String msg = messageSource.getMessage("internalServerError", null, LocaleContextHolder.getLocale());
            node.put("message", msg);
        }

        SecUtil.writeCorsHeaders(request, response);
        response.addHeader("Content-Type", "application/json; charset=utf-8");
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(response.getOutputStream(), StandardCharsets.UTF_8));
        writer.write(mapper.writeValueAsString(node));
        writer.flush();
        writer.close();
    }

    private LoginRequest getLoginRequest(HttpServletRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(request.getInputStream(), LoginRequest.class);
    }

    @Override
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
