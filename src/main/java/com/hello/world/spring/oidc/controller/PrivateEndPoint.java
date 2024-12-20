package com.hello.world.spring.oidc.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class PrivateEndPoint {

    @RequestMapping("/private")
    public String privateEndpoint() {
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();

        Set<String> roles = authentication.getAuthorities().stream()
                .map(r -> r.getAuthority()).collect(Collectors.toSet());

        return "<!DOCTYPE html>\n" + "<html>\n" + "\n" + "  <h1>Hello World!</h1>\n"
                + "  <p>User:</p>\n" +currentPrincipalName
                + "  <p>Roles:</p>\n"  + roles
                + "\n" + "</body>\n" + "</html>\n";
    }

}
