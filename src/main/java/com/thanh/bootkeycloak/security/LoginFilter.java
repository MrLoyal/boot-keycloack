package com.thanh.bootkeycloak.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thanh.bootkeycloak.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
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

public class LoginFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger logger = LoggerFactory.getLogger(LoginFilter.class);

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

        if (authResult instanceof KeyCloackAuthenticationToken) {
            KeyCloackAuthenticationToken token = (KeyCloackAuthenticationToken) authResult;
            ObjectMapper mapper = new ObjectMapper();

            LoginSuccessResponse loginSuccessResponse = new LoginSuccessResponse();
            loginSuccessResponse.setAccessToken(token.getAccessToken());
            loginSuccessResponse.setRefreshToken(token.getRefreshToken());

            String str = mapper.writeValueAsString(loginSuccessResponse);

            response.setStatus(200);
            SecUtil.writeCorsHeaders(request, response);
            response.addHeader("Content-Type", "application/json");
            BufferedWriter writer = new BufferedWriter(response.getWriter());
            writer.write(str);
            writer.flush();
            writer.close();
        } else {
            logger.warn("authResult is not of type KeyCloackAuthenticationToken");
        }
    }


    private LoginRequest getLoginRequest(HttpServletRequest request) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(request.getInputStream(), LoginRequest.class);
    }
}
