package com.thanh.bootkeycloak.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class HiController {

    @RequestMapping("/hi")
    @PreAuthorize("hasAuthority('user')")
    public JsonNode sayHi(HttpServletRequest request) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode node = mapper.createObjectNode();
        node.put("message", "Hello " + request.getHeader("User-Agent"));
        return node;
    }
}
