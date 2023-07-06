package com.coding.auth.config;

import com.coding.auth.jose.Jwks;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2ClientAuthenticationConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import javax.sql.DataSource;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Configuration
public class AuthorizationServerConfig {


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService oAuth2AuthorizationService,
            OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService,
            AuthorizationServerSettings authorizationServerSettings) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter
                = new DeviceClientAuthenticationConverter(authorizationServerSettings.getDeviceAuthorizationEndpoint());

        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider
                = new DeviceClientAuthenticationProvider(registeredClientRepository);


        // @formatter:off
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .deviceAuthorizationEndpoint(oAuth2DeviceAuthorizationEndpointConfigurer ->
                        oAuth2DeviceAuthorizationEndpointConfigurer.verificationUri("/activate"))
                .deviceVerificationEndpoint(oAuth2DeviceVerificationEndpointConfigurer ->
                        oAuth2DeviceVerificationEndpointConfigurer.consentPage("/oauth2/consent"))
                .clientAuthentication(oAuth2ClientAuthenticationConfigurer ->
                        oAuth2ClientAuthenticationConfigurer.authenticationProvider(deviceClientAuthenticationProvider)
                                .authenticationConverter(deviceClientAuthenticationConverter))
                .oidc(Customizer.withDefaults())
                .authorizationService(oAuth2AuthorizationService)
                .registeredClientRepository(registeredClientRepository)
                .authorizationConsentService(oAuth2AuthorizationConsentService);
//                .clientAuthentication(oAuth2ClientAuthenticationConfigurer -> oAuth2ClientAuthenticationConfigurer.authenticationProvider(clientSecretAuthenticationProvider));
        // @formatter:on

        // @formatter:off
        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(Customizer.withDefaults()));

        http.cors(Customizer.withDefaults());

        // @formatter:on
        return http.build();
    }

    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("client-client")
                        .clientName("client-client")
                        .clientIdIssuedAt(Instant.now())
                        .clientSecret(passwordEncoder.encode("client-client"))
                        .clientSecretExpiresAt(Instant.now().plus(14, ChronoUnit.DAYS))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
                        .scope("message.read")
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                        .tokenSettings(TokenSettings.builder()
                                //access token 有效期
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                .build())
                .build());
////        // 授权码模式
        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("code-client")
                        .clientName("code-client")
                        .clientIdIssuedAt(Instant.now())
                        .clientSecret(passwordEncoder.encode("code-client"))
                        .clientIdIssuedAt(Instant.now())
                        .clientSecretExpiresAt(Instant.now().plus(14, ChronoUnit.DAYS))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1:8080/callback")
                        .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .scope("message.read")
                        .scope("message.write")
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                        .tokenSettings(TokenSettings.builder()
                                //access token 有效期
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                //refresh token 有效期
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                //执行刷新token时， 是否返回新的refresh token (默认true 既是重用 refresh token; false 则生成新的 refresh token 及有效期)
                                .reuseRefreshTokens(true)
                                .build())
                        .build());
//
//        // 授权码 + PKCE 模式
        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("oidc-client")
                        .clientIdIssuedAt(Instant.now())
                        .clientSecret(passwordEncoder.encode("oidc-client"))
                        .clientSecretExpiresAt(Instant.now().plus(14, ChronoUnit.DAYS))
                        .clientName("oidc-client")
                        .redirectUri("http://127.0.0.1:8080/callback")
                        .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
                //客户端认证方 none - 若开启PKCE 认证， 则需要添加 none，认证方法
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PHONE)
                        .scope(OidcScopes.EMAIL)
                        .scope(OidcScopes.PROFILE)
                        .scope(OidcScopes.ADDRESS)
                        .scope("offline_access")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                //是否需要开启PKCE模式
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                //access token 有效期
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                .build())
                .build());


        registeredClientRepository.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device-client")
                .clientIdIssuedAt(Instant.now())
                .clientName("device-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/logout")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .scope("message.read")
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(60))
                                 //refresh token 有效期
                                .refreshTokenTimeToLive(Duration.ofDays(7))
                                //执行刷新token时， 是否返回新的refresh token (默认true 既是重用 refresh token; false 则生成新的 refresh token 及有效期)
                                .reuseRefreshTokens(true)
                                .build())
                .build()
        );

        return registeredClientRepository;
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
//        return new FederatedIdentityIdTokenCustomizer();
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

//    @Bean
//    public ClientSecretAuthenticationProvider clientSecretAuthenticationProvider(RegisteredClientRepository registeredClientRepository ,OAuth2AuthorizationService authorizationService ,PasswordEncoder passwordEncoder) {
//        ClientSecretAuthenticationProvider clientSecretAuthenticationProvider = new ClientSecretAuthenticationProvider(registeredClientRepository, authorizationService);
//        clientSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
//        return clientSecretAuthenticationProvider;
//    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public PasswordEncoder passwordEncoder () {
        return new BCryptPasswordEncoder();
    }


}
