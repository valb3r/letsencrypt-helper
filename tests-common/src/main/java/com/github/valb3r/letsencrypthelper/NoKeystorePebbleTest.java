package com.github.valb3r.letsencrypthelper;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@ActiveProfiles("test-missing-keystore")
public abstract class NoKeystorePebbleTest extends BaseTest {

    @Test
    void testWhenNoKeystoreNewCertificateGranted() {
        assertThat(callHelloAndGetIssuerDn()).isEqualTo("CN=letsencrypt-java-helper");
        launchPebbleContainers();
        await().atMost(TIMEOUT).until(() -> callHelloAndGetIssuerDn().contains("Pebble"));
        assertThat(callHelloAndGetIssuerDn()).startsWith("CN=Pebble Intermediate CA");
    }
}
