package com.github.valb3r.letsencrypt;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

public class HttpUtil {

    public static Certificate[] httpGet(URL url, String expectedBody) {
        try {
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setHostnameVerifier((string, ssls) -> true);
            connection.setSSLSocketFactory(prepareContext().getSocketFactory());
            assertThat(connection.getResponseCode()).isEqualTo(200);
            assertThat(connection.getInputStream().readAllBytes()).asString(StandardCharsets.UTF_8).isEqualTo(expectedBody);
            Certificate[] certificates = connection.getServerCertificates();
            connection.disconnect();
            return certificates;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static URL helloUrl() {
        try {
            return new URL("https://localhost:8443/hello");
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    private static SSLContext prepareContext() {
        try {
            SSLContext sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(null, new TrustManager[] {new SSLTrustingX509TrustManager()}, null);
            return sslCtx;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    private static class SSLTrustingX509TrustManager implements X509TrustManager {
        private X509Certificate[] accepted;

        @Override
        public void checkClientTrusted(X509Certificate[] xcs, String string) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] xcs, String string) {
            accepted = xcs;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return accepted;
        }
    }
}
