package com.hello.world.spring.oidc.controller;


import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PublicEndPoint {

    @RequestMapping("/public")
    public String publicEndpoint() {
        return "Hello Public World!";
    }

}