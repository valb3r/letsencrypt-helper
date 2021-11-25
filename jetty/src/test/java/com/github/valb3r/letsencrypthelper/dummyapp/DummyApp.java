package com.github.valb3r.letsencrypthelper.dummyapp;

import com.github.valb3r.letsencrypthelper.JettyWellKnownLetsEncryptChallengeEndpointConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({JettyWellKnownLetsEncryptChallengeEndpointConfig.class})
public class DummyApp {

    public static void main(String[] args) {
        SpringApplication.run(DummyApp.class);
    }
}
