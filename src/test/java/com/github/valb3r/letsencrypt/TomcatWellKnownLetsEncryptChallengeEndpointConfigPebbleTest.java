package com.github.valb3r.letsencrypt;

import com.github.valb3r.letsencrypt.dummyapp.DummyApp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.DockerComposeContainer;
import org.testcontainers.containers.FixedHostPortGenericContainer;
import org.testcontainers.containers.GenericContainer;

import java.io.File;
import java.security.cert.X509Certificate;
import java.time.Duration;

import static com.github.valb3r.letsencrypt.HttpUtil.helloUrl;
import static com.github.valb3r.letsencrypt.HttpUtil.httpGet;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@ActiveProfiles("test-missing-keystore")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = DummyApp.class)
class TomcatWellKnownLetsEncryptChallengeEndpointConfigPebbleTest {

    public static final Duration TIMEOUT = Duration.ofMinutes(1);

    public static GenericContainer<?> PEBBLE;
    public static GenericContainer<?> PEBBLE_CHALL;

    @AfterEach
    public void stop() {
        PEBBLE.stop();
        PEBBLE_CHALL.stop();
        new File("test-keystore").delete();
    }

    @Test
    void testWhenNoKeystoreNewCertificateGranted() {
        assertThat(callHelloAndGetIssuerDn()).isEqualTo("CN=letsencrypt-java-helper");
        launchPebbleContainers();
        await().atMost(TIMEOUT).until(() -> callHelloAndGetIssuerDn().contains("Pebble"));
        assertThat(callHelloAndGetIssuerDn()).startsWith("CN=Pebble Intermediate CA");
    }

    @Test
    void testWhenExpiredCertificateNewGranted() {
    }

    @Test
    void testWhenValidNoNewCertificateGranted() {
    }

    private String callHelloAndGetIssuerDn() {
        var certs = httpGet(helloUrl(), "hello");
        assertThat(certs).hasSize(1);
        return ((X509Certificate) certs[0]).getIssuerDN().getName();
    }

    private static void launchPebbleContainers() {
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
