package com.github.valb3r.letsencrypthelper.jetty;

import com.github.valb3r.letsencrypthelper.NotExpiredKeystorePebbleTest;
import org.springframework.context.annotation.Import;

@Import(DisableJettySniConfig.class)
class JettyNotExpiredKeystorePebbleTest extends NotExpiredKeystorePebbleTest {
}
