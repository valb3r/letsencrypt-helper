package com.github.valb3r.letsencrypthelper;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.AbstractProtocol;
import org.apache.tomcat.util.net.AbstractEndpoint;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.SimpleUrlHandlerMapping;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * This configuration class is responsible for maintaining KeyStore with LetsEncrypt certificates.
 *
 * By default, this bean will try to use server.ssl.* configuration variables, so you need to configure your Tomcat SSL properly.
 * In addition to {@code server.ssl.*} , the library requires
 * {@code lets-encrypt-helper.domain} Domain for which the certificate is going to be issued,
 * {@code lets-encrypt-helper.contact} Email or other contact for LetsEncrypt - i.e. {@code mailto:foo@example.com},
 * {@code lets-encrypt-helper.account-key-password} Password for Domain/User keys.
 * If the KeyStore does not exist at the moment application is started, this bean will try to issue the certificate
 * After start, this bean will watch LetsEncrypt certificate for expiration and will reissue certificate if it is close to its expiration.
 *
 * Note: It will use same KeyStore to store your Certificate, Domain key and User key.
 */
@Configuration
@ConditionalOnProperty(value = "server.ssl.enabled", havingValue = "true")
public class TomcatWellKnownLetsEncryptChallengeEndpointConfig implements TomcatConnectorCustomizer, ApplicationListener<ApplicationReadyEvent> {
    public static final String DUMMY_CN = "CN=letsencrypt-java-helper";
    private final Logger logger = LoggerFactory.getLogger(TomcatWellKnownLetsEncryptChallengeEndpointConfig.class);

    private final String domain;
    private final String contactEmail;
    private final String letsEncryptServer;
    private final int keySize;
    private final Duration updateBeforeExpiry;
    private final Duration busyWaitInterval;
    private final String accountKeyAlias;
    private final boolean enabled;
    private final ServerProperties serverProperties;

    private final Map<String, String> challengeTokens = new ConcurrentHashMap<>();
    private final List<Endpoint> observedEndpoints = new CopyOnWriteArrayList<>();
    private final AtomicBoolean customized = new AtomicBoolean();

    public TomcatWellKnownLetsEncryptChallengeEndpointConfig(
            ServerProperties serverProperties,
            @Value("${lets-encrypt-helper.domain}") String domain,
            @Value("${lets-encrypt-helper.contact}") String contact,
            @Value("${lets-encrypt-helper.account-key-alias:letsencrypt-user}") String accountKeyAlias,
            @Value("${lets-encrypt-helper.letsencrypt-server:acme://letsencrypt.org}") String letsEncryptServer,
            @Value("${lets-encrypt-helper.key-size:2048}") int keySize,
            @Value("${lets-encrypt-helper.update-before-expiry:P7D}") Duration updateBeforeExpiry,
            @Value("${lets-encrypt-helper.busy-wait-interval:PT1M}") Duration busyWaitInterval,
            @Value("${lets-encrypt-helper.enabled:true}") boolean enabled
    ) {
        Security.addProvider(new BouncyCastleProvider());
        this.serverProperties = serverProperties;
        this.domain = domain;
        this.contactEmail = contact;
        this.letsEncryptServer = letsEncryptServer;
        this.keySize = keySize;
        this.updateBeforeExpiry = updateBeforeExpiry;
        this.busyWaitInterval = busyWaitInterval;
        this.accountKeyAlias = accountKeyAlias;
        this.enabled = enabled;

        if (null == this.serverProperties.getSsl()) {
            throw new IllegalStateException("SSL is not configured");
        }

        if (null == this.serverProperties.getSsl().getKeyStore()) {
            throw new IllegalStateException("KeyStore is not configured");
        }

        if (null == this.serverProperties.getSsl().getKeyStorePassword()) {
            throw new IllegalStateException("Missing keystore password");
        }

        if (null == this.serverProperties.getSsl().getKeyAlias()) {
            throw new IllegalStateException("Missing key alias");
        }
    }

    @Override
    public void customize(Connector connector) {
        if (!enabled) {
            return;
        }

        createBasicKeystoreIfMissing();

        var protocol = connector.getProtocolHandler();
        if (!(protocol instanceof AbstractProtocol)) {
            logger.info("Impossible to customize protocol {} for connector {}", connector.getProtocolHandler(), connector);
            return;
        }

        try {
            var method = AbstractProtocol.class.getDeclaredMethod("getEndpoint");
            method.setAccessible(true);
            var endpoint = (AbstractEndpoint<?, ?>) method.invoke(protocol);
            if (!endpoint.isSSLEnabled()) {
                logger.info("Endpoint {}:{} is not SSL enabled", endpoint.getClass().getCanonicalName(), endpoint.getPort());
                return;
            }

            var sslConfig = Arrays.stream(endpoint.findSslHostConfigs())
                    .filter(it -> null != it.getCertificateKeystoreFile())
                    .filter(it -> it.getCertificateKeystoreFile().contains(serverProperties.getSsl().getKeyStore()))
                    .filter(it -> serverProperties.getSsl().getKeyStorePassword().equals(it.getCertificateKeystorePassword()))
                    .findFirst()
                    .orElse(null);

            if (null == sslConfig) {
                logger.info("Endpoint {}:{} has different KeyStore file", endpoint.getClass().getCanonicalName(), endpoint.getPort());
                return;
            }

            File keystore = getKeystoreFile();
            if (keystore.exists() && !keystore.canWrite()) {
                throw new IllegalStateException("Unable to write to: " + serverProperties.getSsl().getKeyStore());
            } else if (!keystore.exists()) {
                throw new IllegalStateException("No Keystore: " + serverProperties.getSsl().getKeyStore());
            }

            Endpoint observe = createObservableEndpoint(endpoint, sslConfig);
            if (observe == null) {
                return;
            }

            observedEndpoints.add(observe);
            if (customized.compareAndSet(false, true)) {
                new Thread(this::letsEncryptCheckCertValidityAndRotateIfNeeded).start();
            }
        } catch (NoSuchMethodException|InvocationTargetException|IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (observedEndpoints.isEmpty()) {
            throw new IllegalStateException("Failed to configure LetsEncrypt");
        }
    }

    @Bean
    public SimpleUrlHandlerMapping wellKnownLetsEncryptHook(WellKnownLetsEncryptChallenge challenge) {
        SimpleUrlHandlerMapping simpleUrlHandlerMapping = new SimpleUrlHandlerMapping();
        simpleUrlHandlerMapping.setOrder(Integer.MAX_VALUE - 2); // Launch before ResourceHttpRequestHandler
        Map<String, Object> urlMap = new HashMap<>();
        urlMap.put("/.well-known/acme-challenge/*", challenge);
        simpleUrlHandlerMapping.setUrlMap(urlMap);

        return simpleUrlHandlerMapping;
    }

    @Bean
    WellKnownLetsEncryptChallenge wellKnownLetsEncryptChallenge() {
        return new WellKnownLetsEncryptChallenge(challengeTokens);
    }

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> servletContainer() {
        return server -> {
            if (server != null) {
                server.addAdditionalTomcatConnectors(httpToHttpsRedirectConnector());
            }
        };
    }


    private void createBasicKeystoreIfMissing() {
        File keystoreFile = getKeystoreFile();
        if (keystoreFile.exists()) {
            logger.info("KeyStore exists: {}", keystoreFile.getAbsolutePath());
            return;
        }

        var keystore = createBasicKeystoreWithSelfSignedCert();
        saveKeystore(keystoreFile, keystore);
        logger.info("Created basic (dummy cert, real account/domain keys) KeyStore: {}", keystoreFile.getAbsolutePath());
    }

    private Endpoint createObservableEndpoint(AbstractEndpoint<?, ?> endpoint, SSLHostConfig sslConfig) {
        var observe = new Endpoint(sslConfig, endpoint);
        var ks = tryToReadKeystore();
        var cert = tryToReadCertificate(observe, ks);
        if (null == cert) {
            logger.warn(
                    "For Endpoint {}:{} unable to read certificate from {}",
                    endpoint.getClass().getCanonicalName(),
                    endpoint.getPort(),
                    sslConfig.getCertificateKeystoreFile()
            );
            return null;
        }
        return observe;
    }

    private Connector httpToHttpsRedirectConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setScheme("http");
        connector.setPort(80);
        connector.setSecure(false);
        connector.setRedirectPort(443);
        return connector;
    }

    private File getKeystoreFile() {
        return new File(parseCertificateKeystoreFilePath(serverProperties.getSsl().getKeyStore()));
    }

    private void saveKeystore(File keystoreFile, KeyStore keystore) {
        try (var os = Files.newOutputStream(keystoreFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            keystore.store(os, serverProperties.getSsl().getKeyStorePassword().toCharArray());
        } catch (CertificateException|KeyStoreException|NoSuchAlgorithmException|IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    private void letsEncryptCheckCertValidityAndRotateIfNeeded() {
        while (true) {
            try {
                executeCheckCertValidityAndRotateIfNeeded();
                Thread.sleep(busyWaitInterval.toMillis());
            } catch (InterruptedException ex) {
                logger.info("LetsEncrypt update interrupted", ex);
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void executeCheckCertValidityAndRotateIfNeeded() {
        var ks = tryToReadKeystore();
        for (var endpoint : observedEndpoints) {
            var cert = tryToReadCertificate(endpoint, ks);
            if (null == cert) {
                logger.warn("Certificate is null on {}:{} from {}",
                        endpoint.getTomcatEndpoint().getClass(),
                        endpoint.getTomcatEndpoint().getPort(),
                        endpoint.getHostConfig().getCertificateKeystoreFile()
                );
                continue;
            }

            if (Instant.now().isBefore(cert.getNotAfter().toInstant().minus(updateBeforeExpiry))) {
                continue;
            }

            try {
                updateCertificateAndKeystore(ks);
                endpoint.getTomcatEndpoint().reloadSslHostConfigs();
            } catch (RuntimeException ex) {
                logger.warn("Failed updating KeyStore", ex);
            }
        }
    }

    private KeyStore createBasicKeystoreWithSelfSignedCert() {
        try {
            KeyPair accountKey = KeyPairUtils.createKeyPair(keySize);
            KeyPair domainKey = KeyPairUtils.createKeyPair(keySize);

            var newKeystore = KeyStore.getInstance(serverProperties.getSsl().getKeyStoreType());
            newKeystore.load(null, null);
            var signedAccount = selfSign(accountKey, Instant.now(), Instant.now().plus(Duration.ofDays(3650)));
            var signedDomain = selfSign(domainKey, Instant.now().minus(Duration.ofDays(3650)), Instant.now().minus(Duration.ofDays(3650)));
            newKeystore.setKeyEntry(serverProperties.getSsl().getKeyAlias(), domainKey.getPrivate(), keyPassword().toCharArray(), new Certificate[] { signedDomain });
            newKeystore.setKeyEntry(accountKeyAlias, accountKey.getPrivate(), keyPassword().toCharArray(), new Certificate[] { signedAccount });
            return newKeystore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private Certificate selfSign(KeyPair keyPair, Instant notBefore, Instant notAfter) {
        X500Name dnName = new X500Name(DUMMY_CN);
        BigInteger certSerialNumber = BigInteger.valueOf(Instant.now().toEpochMilli());
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                dnName,
                certSerialNumber,
                Date.from(notBefore),
                Date.from(notAfter),
                dnName,
                subjectPublicKeyInfo
        );
        try {
            var contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keyPair.getPrivate());
            X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
            return new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException | OperatorCreationException ex) {
            throw new RuntimeException(ex);
        }

    }

    private void updateCertificateAndKeystore(KeyStore ks) {
        Session session = new Session(letsEncryptServer);
        URI tos;
        try {
            tos = session.getMetadata().getTermsOfService();
            if (null != tos) {
                logger.warn("Please review carefully and accept TOS {}", tos);
            }

            var accountKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(accountKeyAlias, new KeyStore.PasswordProtection(keyPassword().toCharArray()));
            var domainKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(serverProperties.getSsl().getKeyAlias(), new KeyStore.PasswordProtection(keyPassword().toCharArray()));
            var accountKey = new KeyPair(accountKeyEntry.getCertificate().getPublicKey(), accountKeyEntry.getPrivateKey());
            var domainKey = new KeyPair(domainKeyEntry.getCertificate().getPublicKey(), domainKeyEntry.getPrivateKey());

            Account account = new AccountBuilder()
                    .addContact(contactEmail)
                    .agreeToTermsOfService()
                    .useKeyPair(accountKey)
                    .create(session);

            Order order = account.newOrder().domains(domain).create();
            logger.info("Starting order challenges");
            for (var auth : order.getAuthorizations()) {
                if (auth.getStatus() != Status.PENDING) {
                    continue;
                }

                var challenge = auth.findChallenge(Http01Challenge.class);
                if (null == challenge) {
                    throw new IllegalStateException("Requires non-http challenge");
                }
                challengeTokens.put(challenge.getToken(), challenge.getAuthorization());
                challenge.trigger();

                waitForAuthStatus(auth, Set.of(Status.PENDING, Status.PROCESSING));
            }
            logger.info("Completed order challenges");

            CSRBuilder csrb = new CSRBuilder();
            csrb.addDomain(domain);
            csrb.sign(domainKey);
            byte[] csr = csrb.getEncoded();

            finalizeOrder(order, csr);
            logger.info("Order finalized");

            var certificate = order.getCertificate();
            if (null == certificate) {
                throw new IllegalStateException("Failed to obtain certificate");
            }
            ks.setKeyEntry(serverProperties.getSsl().getKeyAlias(), domainKey.getPrivate(), keyPassword().toCharArray(), new Certificate[] { certificate.getCertificate() });
            saveKeystore(getKeystoreFile(), ks);
            logger.info("KeyStore updated");
        } catch (AcmeException | IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new RuntimeException(e);
        }
    }

    private void finalizeOrder(Order order, byte[] csrb) throws AcmeException {
        order.execute(csrb);
        waitForOrderStatus(order, Set.of(Status.PENDING, Status.PROCESSING, Status.READY));
    }

    private void waitForAuthStatus(Authorization auth, Set<Status> authNotInStatus) throws AcmeException {
        // Wait for the order to complete
        try {
            int attempts = 10;
            while (authNotInStatus.contains(auth.getStatus()) && attempts-- > 0) {
                if (auth.getStatus() == Status.INVALID) {
                    logger.error("Authorization has failed");
                    throw new AcmeException("Authorization failed... Giving up.");
                }

                Thread.sleep(3000L);
                auth.update();
            }
        } catch (InterruptedException ex) {
            logger.error("Interrupted", ex);
            Thread.currentThread().interrupt();
        }
    }

    private void waitForOrderStatus(Order order, Set<Status> orderNotInStatus) throws AcmeException {
        // Wait for the order to complete
        try {
            int attempts = 10;
            while (orderNotInStatus.contains(order.getStatus()) && attempts-- > 0) {
                if (order.getStatus() == Status.INVALID) {
                    logger.error("Order has failed, reason: {}", order.getError());
                    throw new AcmeException("Order failed... Giving up.");
                }

                Thread.sleep(3000L);
                order.update();
            }
        } catch (InterruptedException ex) {
            logger.error("Interrupted", ex);
            Thread.currentThread().interrupt();
        }
    }

    private KeyStore tryToReadKeystore() {
        return tryToReadKeystore(serverProperties.getSsl().getKeyStoreType(), serverProperties.getSsl().getKeyStorePassword());
    }

    private KeyStore tryToReadKeystore(String keystoreType, String keystorePassword) {
        try {
            var ks = KeyStore.getInstance(keystoreType);
            try (var is = Files.newInputStream(getKeystoreFile().toPath())) {
                ks.load(is, keystorePassword.toCharArray());
            } catch (NoSuchAlgorithmException|IOException|CertificateException e) {
                logger.warn("Failed reading KeyStore of type {}", keystoreType, e);
                return null;
            }

            return ks;
        } catch (KeyStoreException ex) {
            logger.warn("Failed creating KeyStore of type {}", keystoreType, ex);
            return null;
        }
    }

    private X509Certificate tryToReadCertificate(Endpoint endpoint, KeyStore ks) {
        if (null == ks) {
            throw new IllegalStateException("Missing KeyStore: " + serverProperties.getSsl().getKeyStore());
        }

        String keyAlias = endpoint.getHostConfig().getCertificateKeyAlias();
        Certificate certificate;
        try {
            certificate = ks.getCertificate(keyAlias);
        } catch (KeyStoreException e) {
            logger.warn("Failed reading certificate {} from {}", keyAlias, serverProperties.getSsl().getKeyStore());
            return null;
        }

        if (certificate instanceof X509Certificate) {
            return (X509Certificate) certificate;
        }

        return null;
    }

    private String parseCertificateKeystoreFilePath(String path) {
        return path.replaceAll("file://", "").replaceAll("file:", "");
    }

    private String keyPassword() {
        return null == serverProperties.getSsl().getKeyPassword() ? serverProperties.getSsl().getKeyStorePassword() : serverProperties.getSsl().getKeyPassword();
    }

    public static class WellKnownLetsEncryptChallenge extends AbstractController {

        private final Map<String, String> challengeToken;

        public WellKnownLetsEncryptChallenge(Map<String, String> challengeToken) {
            this.challengeToken = challengeToken;
        }

        @Override
        protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) {
            var res = new ModelAndView();
            var split = request.getServletPath().split("/");
            var token = split[split.length - 1];
            response.setStatus(HttpStatus.OK.value());
            try {
                response.getWriter().write(challengeToken.get(token));
                response.getWriter().flush();
                return res;
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    private static class Endpoint {
        private final SSLHostConfig hostConfig;
        private final AbstractEndpoint<?, ?> tomcatEndpoint;

        public Endpoint(SSLHostConfig hostConfig, AbstractEndpoint<?, ?> tomcatEndpoint) {
            this.hostConfig = hostConfig;
            this.tomcatEndpoint = tomcatEndpoint;
        }

        public SSLHostConfig getHostConfig() {
            return hostConfig;
        }

        public AbstractEndpoint<?, ?> getTomcatEndpoint() {
            return tomcatEndpoint;
        }
    }
}
