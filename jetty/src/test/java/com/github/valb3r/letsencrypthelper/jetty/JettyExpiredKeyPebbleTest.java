package com.github.valb3r.letsencrypthelper.jetty;

import com.github.valb3r.letsencrypthelper.ExpiredKeyPebbleTest;
import org.springframework.context.annotation.Import;

@Import(DisableJettySniConfig.class)
class JettyExpiredKeyPebbleTest extends ExpiredKeyPebbleTest {
}
