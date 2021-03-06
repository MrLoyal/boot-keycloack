package com.thanh.bootkeycloak.security;

import com.thanh.bootkeycloak.util.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private KeyCloakProperties keyCloakProperties;
    private MessageSource messageSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .authenticationProvider(authenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .addFilterAfter(loginFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(keyCloakAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(Constants.LOGIN_URL).permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new UnauthorizedAuthenticationEntryPoint());
    }

    @Bean
    public FilterRegistrationBean<KeyCloakAuthenticationFilter> filterRegistrationBean(KeyCloakAuthenticationFilter keyCloakAuthenticationFilter) {
        FilterRegistrationBean<KeyCloakAuthenticationFilter> registrar = new FilterRegistrationBean<>(keyCloakAuthenticationFilter);
        registrar.setEnabled(false);
        return registrar;
    }

    @Bean
    public KeyCloakAuthenticationProvider authenticationProvider() {
        KeyCloakAuthenticationProvider provider = new KeyCloakAuthenticationProvider();
        provider.setKeyCloakProperties(keyCloakProperties);
        return provider;
    }

    @Bean
    public LoginFilter loginFilter() throws Exception {
        LoginFilter filter = new LoginFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setMessageSource(messageSource);
        return filter;
    }

    @Bean
    public KeyCloakAuthenticationFilter keyCloakAuthenticationFilter() {
        KeyCloakAuthenticationFilter filter = new KeyCloakAuthenticationFilter(keyCloakProperties);
        filter.setMessageSource(messageSource);
        return filter;
    }

    @Autowired
    public void setKeyCloakProperties(KeyCloakProperties keyCloakProperties) {
        this.keyCloakProperties = keyCloakProperties;
    }

    @Autowired
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
