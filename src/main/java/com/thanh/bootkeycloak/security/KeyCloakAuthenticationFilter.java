package com.thanh.bootkeycloak.security;


import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class KeyCloakAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(KeyCloakAuthenticationFilter.class);
    private KeyCloakProperties keyCloakProperties;
    private MessageSource messageSource;

    public KeyCloakAuthenticationFilter(KeyCloakProperties keyCloakProperties) {
        this.keyCloakProperties = keyCloakProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        UsernamePasswordAuthenticationToken authentication = null;
        if (accessToken != null) {
            try {
                DecodedJWT jwt = JWT.decode(accessToken);
                OpenIdConnectUrlJwkProvider.setKeyCloakProperties(keyCloakProperties);
                OpenIdConnectUrlJwkProvider provider = new OpenIdConnectUrlJwkProvider(keyCloakProperties.getServiceUri());
                Jwk jwk = provider.get(jwt.getKeyId());
                Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
                algorithm.verify(jwt);

                Date exp = jwt.getExpiresAt();
                if (exp.before(new Date())) {
                    writeExpiredResponse(request, response);
                } else {

                    String username = jwt.getClaim("preferred_username").asString();

                    Claim realmAccess = jwt.getClaim("realm_access");
                    Map<String, Object> realmAccessMap = realmAccess.asMap();
                    List roles = (List) realmAccessMap.get("roles");
                    List<GrantedAuthority> authorities = new ArrayList<>();
                    if (roles != null && !roles.isEmpty()) {
                        for (Object obj : roles) {
                            if (obj != null) {
                                authorities.add(new SimpleGrantedAuthority(obj.toString()));
                            }
                        }
                    }

                    authentication = new UsernamePasswordAuthenticationToken(username, "[Protected]", authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    filterChain.doFilter(request, response);
                }


            } catch (JwkException e) {
                logger.error("", e);
                filterChain.doFilter(request, response);
            }
        } else {
            filterChain.doFilter(request, response);
        }


    }

    private void writeExpiredResponse(HttpServletRequest request, HttpServletResponse response) {
        response.reset();
        response.setStatus(401);
        response.setHeader("Content-Type", "application/json; charset=utf-8");
        SecUtil.writeCorsHeaders(request, response);
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("code", "ACCESS_TOKEN_EXPIRED");
        String message = messageSource.getMessage("tokenExpired", null, LocaleContextHolder.getLocale());

        node.put("message", message);
        try {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(response.getOutputStream(), StandardCharsets.UTF_8));
            writer.write(mapper.writeValueAsString(node));
            writer.flush();
            writer.close();
        } catch (IOException e) {
            logger.error("", e);
        }
    }

    private String getAccessToken(HttpServletRequest request) {
        String accessToken = request.getHeader("Authorization");
        if (accessToken == null) {
            accessToken = request.getParameter("accessToken");
        }
        if (accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7);
        }
        return accessToken;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
