[![](https://jitpack.io/v/valb3r/letsencrypt-helper.svg)](https://jitpack.io/#valb3r/letsencrypt-helper)

# What is this

This library allows obtaining and updating (renewing) LetsEncrypt SSL certificate automatically for your Spring-Boot Web application.
With this library, you do not need `CertBot` or docker-sidecar with i.e. `Traefik` to get LetsEncrypt certificate,
everything will be done inside your Java application.

The library will **automatically**  :
1. Obtain LetsEncrypt certificate on fresh start
2. Store generated keys and certificate into single KeyStore (`server.ssl.keystore`)
3. Renew LetsEncrypt certificate (it watches for certificate expiration date and updates it to new before old is expired)

# Application requirements

To perform HTTP-01 ACME challenge, the application must listen on port `80`, this library will automatically create
Tomcat connector to this port, so the only thing needed on your side is to open `80` port for the application.

# Servlet containers supported (embedded)

 - Tomcat
 
# Usage

## From JitPack maven repository

1. Import this library:
    1. [Add JitPack repository to your dependency management system](https://jitpack.io/)
    2. Add this library to your dependencies, [like it is shown here](https://jitpack.io/#valb3r/letsencrypt-helper/0.1.1)
2. Declare `@Import(TomcatWellKnownLetsEncryptChallengeEndpointConfig.class)` on your configuration
3. Define following properties in your application configuration or environment:
    1. `lets-encrypt-helper.domain` the domain to issue certificate for
    2. `lets-encrypt-helper.contact` your contact for LetsEncrypt (i.e. your email in format `mailto:john.doe@example.com`)

## Alternative

The library is itself just 1 Java class. You can add library dependencies and 
[this java file](https://github.com/valb3r/letsencrypt-helper/blob/master/src/main/java/com/github/valb3r/letsencrypthelper/TomcatWellKnownLetsEncryptChallengeEndpointConfig.java)
to your configiration
