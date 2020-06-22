package com.thanh.bootkeycloak.security;


import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeyCloakAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(KeyCloakAuthenticationFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        UsernamePasswordAuthenticationToken authentication = null;
        if (accessToken != null) {
            try {
                DecodedJWT jwt = JWT.decode(accessToken);
                JwkProvider provider = new OpenIdConnectUrlJwkProvider("http://localhost:8080/auth");
                Jwk jwk = provider.get(jwt.getKeyId());
                Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
                algorithm.verify(jwt);

                logger.debug("Claims: =================== \n{}", jwt.getClaims());
                String email = jwt.getClaim("email").asString();
                String username = jwt.getClaim("preferred_username").asString();
                logger.debug("Email ========= {}", email);
                logger.debug("Username ========= {}", username);

                Claim realmAccess = jwt.getClaim("realm_access");
                Map<String, Object> realmAccessMap = realmAccess.asMap();
                List<String> roles = (List<String>) realmAccessMap.get("roles");

                List<SimpleGrantedAuthority> authorities = roles.stream().map(r -> {
                    return new SimpleGrantedAuthority(r);
                }).collect(Collectors.toList());

                authentication = new UsernamePasswordAuthenticationToken(username, "[Protected]", authorities);


            } catch (Exception e) {
                logger.error("", e);
            }
        }

        if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
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
}
