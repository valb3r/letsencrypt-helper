package com.github.valb3r.letsencrypthelper;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@ActiveProfiles("test-expired-keystore")
public abstract class ExpiredKeyPebbleTest extends BaseTest {

    @Test
    void testWhenExpiredKeystoreNewCertificateGranted() {
        assertThat(callHelloAndGetIssuerDn()).isEqualTo("CN=expired-letsencrypt-java-helper");
        launchPebbleContainers();
        await().atMost(TIMEOUT).until(() -> callHelloAndGetIssuerDn().contains("Pebble"));
        assertThat(callHelloAndGetIssuerDn()).startsWith("CN=Pebble Intermediate CA");
    }
}
