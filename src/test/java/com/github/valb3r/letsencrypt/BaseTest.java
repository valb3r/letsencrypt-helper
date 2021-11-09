package com.github.valb3r.letsencrypt;

import com.github.valb3r.letsencrypt.dummyapp.DummyApp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static com.github.valb3r.letsencrypt.HttpUtil.helloUrl;
import static com.github.valb3r.letsencrypt.HttpUtil.httpGet;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = DummyApp.class)
abstract public class BaseTest {

    public static final Duration TIMEOUT = Duration.ofMinutes(1);

    public static GenericContainer<?> PEBBLE;
    public static GenericContainer<?> PEBBLE_CHALL;

    @BeforeEach
    public void init() throws IOException {
        Files.copy(Paths.get("src/test/resources/template-expired-test-keystore"), Paths.get("src/test/resources/expired-test-keystore"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(Paths.get("src/test/resources/template-not-expired-test-keystore"), Paths.get("src/test/resources/not-expired-test-keystore"), StandardCopyOption.REPLACE_EXISTING);
    }

    @AfterEach
    public void stop() {
        PEBBLE.stop();
        PEBBLE_CHALL.stop();
        new File("temp-test-keystore").delete();
    }

    protected String callHelloAndGetIssuerDn() {
        var certs = httpGet(helloUrl(), "hello");
        assertThat(certs).hasSize(1);
        return ((X509Certificate) certs[0]).getIssuerDN().getName();
    }

     static void launchPebbleContainers() {
        Testcontainers.exposeHostPorts(5002);
        PEBBLE = new FixedHostPortGenericContainer<>("letsencrypt/pebble")
                .withCommand("pebble -config /test/config/pebble-config.json -strict")
                .withFixedExposedPort(14000, 14000)
                .withFixedExposedPort(15000, 15000)
                .withAccessToHost(true);
        PEBBLE.start();

        PEBBLE_CHALL = new FixedHostPortGenericContainer<>("letsencrypt/pebble-challtestsrv")
                .withCommand("pebble-challtestsrv -defaultIPv6 \"\"")
                .withFixedExposedPort(8055, 8055)
                .withAccessToHost(true);
        PEBBLE_CHALL.start();
    }
}
