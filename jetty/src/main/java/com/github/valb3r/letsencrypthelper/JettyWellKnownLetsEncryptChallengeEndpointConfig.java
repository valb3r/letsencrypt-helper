package com.github.valb3r.letsencrypthelper;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.eclipse.jetty.http.HttpScheme;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
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
import org.springframework.boot.web.embedded.jetty.ConfigurableJettyWebServerFactory;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * This configuration class is responsible for maintaining KeyStore with LetsEncrypt certificates.
 *
 * By default, this bean will try to use server.ssl.* configuration variables, so you need to configure your Tomcat SSL properly.
 * In addition to properly configured {@code server.ssl.*} for the KeyStore usage (ideally PKCS12), the library requires:
 * {@code lets-encrypt-helper.domain} Domain for which the certificate is going to be issued,
 * {@code lets-encrypt-helper.contact} Email or other contact for LetsEncrypt - i.e. {@code mailto:foo@example.com},
 * If the KeyStore does not exist at the moment application is started, this bean will try to create new KeyStore with self-signed cert and keys
 * After start, this bean will watch LetsEncrypt certificate for expiration and will reissue certificate if it is close to its expiration.
 *
 * Note: It will use same KeyStore to store your Certificate, Domain key and Account key.
 */
@Configuration
@ConditionalOnProperty(value = "server.ssl.enabled", havingValue = "true")
public class JettyWellKnownLetsEncryptChallengeEndpointConfig implements JettyServerCustomizer, ApplicationListener<ApplicationReadyEvent> {
    public static final String DUMMY_CN = "CN=letsencrypt-java-helper";
    private final Logger logger = LoggerFactory.getLogger(JettyWellKnownLetsEncryptChallengeEndpointConfig.class);

    private final int serverPort;

    private final String domain;
    private final String contact;
    private final String letsEncryptServer;
    private final int keySize;
    private final Duration updateBeforeExpiry;
    private final Duration busyWaitInterval;
    private final String accountKeyAlias;
    private final Duration accountCertValidity;
    private final boolean enabled;
    private final ServerProperties serverProperties;

    // Development only properties, you can't change these for production
    private final int http01ChallengePort;
    // End

    private final Map<String, String> challengeTokens = new ConcurrentHashMap<>();
    private final List<TargetProtocol> observedEndpoints = new CopyOnWriteArrayList<>();
    private final AtomicBoolean customized = new AtomicBoolean();

    /**
     * Initialize LetsEncrypt certificate obtaining and renewal class.
     * @param serverProperties - SSL properties (serverProperties.ssl) to be used
     * @param domain - Domain to issue certificate for (i.e. {@code example.com})
     * @param contact - Your email (i.e. {@code mailto:john.doe@example.com})
     * @param accountKeyAlias - Key name to store your Account key-pair (necessary for renewal process)
     * @param letsEncryptServer - LetsEncrypt server to use, as defined in Acme4j. acme://letsencrypt.org is production
     * @param keySize - RSA Key size for Domain and Account keys that are to be generated
     * @param updateBeforeExpiry - Start trying to update certificate {@code updateBeforeExpiry} time before it expires
     * @param busyWaitInterval - How frequently to check if certificate needs update (scheduled-alike busy wait)
     * @param enabled - If the helper is enabled (for i.e. development)
     */
    public JettyWellKnownLetsEncryptChallengeEndpointConfig(
            ServerProperties serverProperties,
            @Value("${server.port}") int serverPort,
            @Value("${lets-encrypt-helper.domain}") String domain,
            @Value("${lets-encrypt-helper.contact}") String contact,
            @Value("${lets-encrypt-helper.account-key-alias:letsencrypt-user}") String accountKeyAlias,
            @Value("${lets-encrypt-helper.letsencrypt-server:acme://letsencrypt.org}") String letsEncryptServer,
            @Value("${lets-encrypt-helper.key-size:2048}") int keySize,
            @Value("${lets-encrypt-helper.update-before-expiry:P7D}") Duration updateBeforeExpiry,
            @Value("${lets-encrypt-helper.busy-wait-interval:PT1M}") Duration busyWaitInterval,
            @Value("${lets-encrypt-helper.account-cert-validity:P3650D}") Duration accountCertValidity,
            @Value("${lets-encrypt-helper.enabled:true}") boolean enabled,
            @Value("${lets-encrypt-helper.development-only.http01-challenge-port:80}") int http01ChallengePort
    ) {
        Security.addProvider(new BouncyCastleProvider());
        this.serverPort = serverPort;
        this.serverProperties = serverProperties;
        this.domain = domain;
        this.contact = contact;
        this.accountKeyAlias = accountKeyAlias;
        this.letsEncryptServer = letsEncryptServer;
        this.keySize = keySize;
        this.updateBeforeExpiry = updateBeforeExpiry;
        this.busyWaitInterval = busyWaitInterval;
        this.accountCertValidity = accountCertValidity;
        this.enabled = enabled;
        this.http01ChallengePort = http01ChallengePort;

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
    public void customize(Server server) {
        if (!enabled) {
            return;
        }

        var sslContextFactories = new ArrayList<SslContextFactory>();
        for (Connector connector : server.getConnectors()) {
            var factory = connector.getConnectionFactory(SslConnectionFactory.class);
            if (null == factory) {
                continue;
            }
            var ctx = factory.getSslContextFactory();
            if (!ctx.getKeyStorePath().contains(serverProperties.getSsl().getKeyStore())
                    || !ctx.getCertAlias().equals(serverProperties.getSsl().getKeyAlias())) {
                continue;
            }
            sslContextFactories.add(ctx);
        }

        if (sslContextFactories.isEmpty()) {
            logger.info("No SSL Context factories found");
            return;
        }

        createBasicKeystoreIfMissing();

        observedEndpoints.addAll(
                sslContextFactories.stream().map(this::createObservableProtocol).collect(Collectors.toList())
        );
        if (customized.compareAndSet(false, true)) {
            new Thread(this::letsEncryptCheckCertValidityAndRotateIfNeeded, "LetsEncrypt Certificate Watcher").start();
        }
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (enabled && observedEndpoints.isEmpty()) {
            throw new IllegalStateException("Failed to configure LetsEncrypt");
        }
    }

    @Bean
    SimpleUrlHandlerMapping wellKnownLetsEncryptHook(WellKnownLetsEncryptChallenge challenge) {
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
    WebServerFactoryCustomizer<ConfigurableJettyWebServerFactory> servletContainer() {
        return factory -> {
            if (factory != null) {
                factory.addServerCustomizers(this::httpToHttpsRedirectConnector);
            }
        };
    }

    protected Instant getNow() {
        return Instant.now();
    }

    private void createBasicKeystoreIfMissing() {
        File keystoreFile = getKeystoreFile();
        if (keystoreFile.exists()) {
            if (!keystoreFile.canWrite()) {
                throw new IllegalArgumentException(String.format("Keystore %s is not writable, certificate update is impossible", keystoreFile.getAbsolutePath()));
            }

            logger.info("KeyStore exists: {}", keystoreFile.getAbsolutePath());
            return;
        }

        var keystore = createBasicKeystoreWithSelfSignedCert();
        saveKeystore(keystoreFile, keystore);
        logger.info("Created basic (dummy cert, real account/domain keys) KeyStore: {}", keystoreFile.getAbsolutePath());
    }

    private TargetProtocol createObservableProtocol(SslContextFactory contextFactory) {
        var observe = new TargetProtocol(contextFactory);
        var ks = tryToReadKeystore();
        var cert = tryToReadCertificate(observe, ks);
        if (null == cert) {
            logger.warn(
                    "For Protocol {}:{} unable to read certificate from {}",
                    contextFactory.getClass().getCanonicalName(),
                    contextFactory.getProtocol(),
                    contextFactory.getKeyStorePath()
            );
            return null;
        }
        return observe;
    }

    private Connector httpToHttpsRedirectConnector(Server server) {
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setSecurePort(serverPort);
        httpConfiguration.setSecureScheme(HttpScheme.HTTPS.asString());

        ServerConnector connector = new ServerConnector(server);
        connector.addConnectionFactory(new HttpConnectionFactory(httpConfiguration));
        connector.setPort(http01ChallengePort);
        return connector;
    }

    private File getKeystoreFile() {
        return new File(parseCertificateKeystoreFilePath(serverProperties.getSsl().getKeyStore()));
    }

    private void saveKeystore(File keystoreFile, KeyStore keystore) {
        try (var os = Files.newOutputStream(keystoreFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            keystore.store(os, serverProperties.getSsl().getKeyStorePassword().toCharArray());
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException ex) {
            logger.error("Failed saving updated keystore", ex);
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
                        endpoint.getSslContextFactory().getClass(),
                        endpoint.getSslContextFactory().getProtocol(),
                        endpoint.getSslContextFactory().getKeyStorePath()
                );
                continue;
            }

            if (getNow().isBefore(cert.getNotAfter().toInstant().minus(updateBeforeExpiry))) {
                continue;
            }

            try {
                updateCertificateAndKeystore(ks);
                endpoint.getSslContextFactory().reload(it -> {});
            } catch (Exception ex) {
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
            var signedAccount = selfSign(accountKey, getNow(), getNow().plus(accountCertValidity));
            var epoch = Instant.parse("1970-01-01T00:00:00Z");
            var signedDomain = selfSign(domainKey, epoch, epoch);
            newKeystore.setKeyEntry(serverProperties.getSsl().getKeyAlias(), domainKey.getPrivate(), keyPassword().toCharArray(), new Certificate[] { signedDomain });
            newKeystore.setKeyEntry(accountKeyAlias, accountKey.getPrivate(), keyPassword().toCharArray(), new Certificate[] { signedAccount });
            return newKeystore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private Certificate selfSign(KeyPair keyPair, Instant notBefore, Instant notAfter) {
        X500Name dnName = new X500Name(DUMMY_CN);
        BigInteger certSerialNumber = BigInteger.valueOf(getNow().toEpochMilli());
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
                    .addContact(contact)
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
        try {
            order.execute(csrb);
        } catch (AcmeException ex) {
            order.update();
            logger.warn("Failed order execution: {}", order.getError(), ex);
            throw ex;
        }

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
            } catch (NoSuchAlgorithmException | IOException | CertificateException e) {
                logger.warn("Failed reading KeyStore of type {}", keystoreType, e);
                return null;
            }

            return ks;
        } catch (KeyStoreException ex) {
            logger.warn("Failed creating KeyStore of type {}", keystoreType, ex);
            return null;
        }
    }

    private X509Certificate tryToReadCertificate(TargetProtocol protocol, KeyStore ks) {
        if (null == ks) {
            throw new IllegalStateException("Missing KeyStore: " + serverProperties.getSsl().getKeyStore());
        }

        String keyAlias = protocol.getSslContextFactory().getCertAlias();
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

    private static class TargetProtocol {
        private final SslContextFactory sslContextFactory;

        public TargetProtocol(SslContextFactory sslContextFactory) {
            this.sslContextFactory = sslContextFactory;
        }

        public SslContextFactory getSslContextFactory() {
            return sslContextFactory;
        }
    }
}
