package com.github.valb3r.letsencrypt.dummyapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DummyRest {
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }
}
