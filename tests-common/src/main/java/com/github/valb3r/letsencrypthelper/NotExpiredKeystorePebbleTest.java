package com.github.valb3r.letsencrypthelper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.ActiveProfiles;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test-not-expired-keystore")
public abstract class NotExpiredKeystorePebbleTest extends BaseTest {

    @Value("${lets-encrypt-helper.busy-wait-interval}")
    private Duration scheduleBeat;

    @Test
    void testWhenNotExpiredKeystoreNoCertificateGranted() throws InterruptedException {
        assertThat(scheduleBeat).isLessThan(Duration.ofSeconds(10));
        assertThat(callHelloAndGetIssuerDn(1)).isEqualTo("CN=not-expired-letsencrypt-java-helper");
        launchPebbleContainers();
        Thread.sleep(TIMEOUT.toMillis());
        assertThat(callHelloAndGetIssuerDn(1)).startsWith("CN=not-expired-letsencrypt-java-helper");
    }
}
