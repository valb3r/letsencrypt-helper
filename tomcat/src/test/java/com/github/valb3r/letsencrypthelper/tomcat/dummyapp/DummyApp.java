package com.github.valb3r.letsencrypthelper.tomcat.dummyapp;

import com.github.valb3r.letsencrypthelper.tomcat.TomcatWellKnownLetsEncryptChallengeEndpointConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({TomcatWellKnownLetsEncryptChallengeEndpointConfig.class})
public class DummyApp {

    public static void main(String[] args) {
        SpringApplication.run(DummyApp.class);
    }
}
