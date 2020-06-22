package com.thanh.bootkeycloak.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class HiController {

    private MessageSource messageSource;

    @RequestMapping("/hi")
    @PreAuthorize("hasAuthority('user')")
    public JsonNode sayHi(HttpServletRequest request) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        String hello = messageSource.getMessage("hello", null, LocaleContextHolder.getLocale());
        node.put("message", hello + " " + request.getHeader("User-Agent"));
        return node;
    }

    @Autowired
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }
}
