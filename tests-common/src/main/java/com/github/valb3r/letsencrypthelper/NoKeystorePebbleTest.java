package com.github.valb3r.letsencrypthelper;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@ActiveProfiles("test-missing-keystore")
public abstract class NoKeystorePebbleTest extends BaseTest {

    @Test
    void testWhenNoKeystoreNewCertificateGranted() {
        assertThat(callHelloAndGetIssuerDn(1)).isEqualTo("CN=letsencrypt-java-helper");
        launchPebbleContainers();
        await().atMost(TIMEOUT).until(() -> callHelloAndGetIssuerDn(null).contains("Pebble"));
        assertThat(callHelloAndGetIssuerDn(2)).startsWith("CN=Pebble Intermediate CA");
    }
}
