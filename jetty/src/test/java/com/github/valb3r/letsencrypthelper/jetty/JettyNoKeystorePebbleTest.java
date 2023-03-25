package com.github.valb3r.letsencrypthelper.jetty;

import com.github.valb3r.letsencrypthelper.NoKeystorePebbleTest;
import org.springframework.context.annotation.Import;

@Import(DisableJettySniConfig.class)
class JettyNoKeystorePebbleTest extends NoKeystorePebbleTest {
}
