package com.hello.world.spring.oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class SpringBootRestfulService {
    public static void main(String[] args) throws Exception {
        new SpringApplication(SpringBootRestfulService.class).run(args);
    }
}
