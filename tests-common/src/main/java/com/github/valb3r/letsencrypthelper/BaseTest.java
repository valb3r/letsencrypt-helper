package com.github.valb3r.letsencrypthelper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.annotation.DirtiesContext;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static com.github.valb3r.letsencrypthelper.HttpUtil.helloUrl;
import static com.github.valb3r.letsencrypthelper.HttpUtil.httpGet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = BaseTest.TestConfig.class)
abstract public class BaseTest {

    public static final Duration TIMEOUT = Duration.ofMinutes(1);

    public static GenericContainer<?> PEBBLE;
    public static GenericContainer<?> PEBBLE_CHALL;

    @Autowired
    private ApplicationContext context;

    @BeforeAll
    public static void init() throws IOException {
        try (var is = BaseTest.class.getClassLoader().getResourceAsStream("template-expired-test-keystore")) {
            Files.copy(is, Paths.get("expired-test-keystore"), StandardCopyOption.REPLACE_EXISTING);
        }
        try (var is = BaseTest.class.getClassLoader().getResourceAsStream("template-not-expired-test-keystore")) {
            Files.copy(is, Paths.get("not-expired-test-keystore"), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @AfterEach
    public void stop() {
        PEBBLE.stop();
        PEBBLE_CHALL.stop();
        await().atMost(TIMEOUT).until(() -> !PEBBLE.isRunning());
        await().atMost(TIMEOUT).until(() -> !PEBBLE_CHALL.isRunning());
        await().atMost(TIMEOUT).until(() -> available(14000) && available(15000) && available(8055));
        new File("temp-test-keystore").delete();
        getThreadByName("LetsEncrypt Certificate Watcher").interrupt();
    }

    public Thread getThreadByName(String threadName) {
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().equals(threadName)) return thread;
        }
        return null;
    }

    protected String callHelloAndGetIssuerDn() {
        var certs = httpGet(helloUrl(), "hello");
        assertThat(certs).hasSize(1);
        return ((X509Certificate) certs[0]).getIssuerDN().getName();
    }

    protected boolean available(int port) {
        try (Socket ignored = new Socket("localhost", port)) {
            return false;
        } catch (IOException ignored) {
            return true;
        }
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

    @Configuration
    @ComponentScan({"com.github.valb3r.letsencrypthelper.tomcat.dummyapp", "com.github.valb3r.letsencrypthelper.jetty.dummyapp"})
    public static class TestConfig {
    }
}
