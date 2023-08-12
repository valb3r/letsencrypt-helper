package com.github.valb3r.letsencrypthelper.jetty;

import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;

@Configuration
public class DisableJettySniConfig implements JettyServerCustomizer {

    @Override
    public void customize(Server server) {
        Arrays.stream(server.getConnectors())
                .forEach(
                        connector -> connector.getConnectionFactory(HttpConnectionFactory.class)
                                .getHttpConfiguration()
                                .getCustomizer(SecureRequestCustomizer.class)
                                .setSniHostCheck(false)
                );
    }
}
