/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hello.world.spring.oidc.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity(debug = false)
public class SecurityConfig {

    @Value("${name.claim}")
    String name_claim;

    @Value("${role.claim:#{null}}")
    String role_claim;

    @Value("${role.prefix:#{null}}")
    String role_prefix;


    @Value("${access.token.aud:#{null}}")
    String access_token_aud;


    @Value("${h2m.client.registration.id}")
    String h2m_client_registration_id;

    @Value("${access.token.issuer.config.metadata:#{null}}")
    String access_token_issuer_config_metadata;


    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.requestMatchers( "/public/**" ).permitAll()
                        .anyRequest().authenticated()
                )
                //h2m
                .oauth2Login(            login ->
                        login
                                //needed when there are multiple registrations
                                .loginPage(getLoginUrl(this.h2m_client_registration_id)) // not provider id
                                .userInfoEndpoint(
                                        endpoint ->
                                                endpoint.oidcUserService(this.oidcUserService(jwtDecoder())))
                )
                //m2m
//                .oauth2ResourceServer(oauth2 ->
//                        oauth2
//                                .jwt(jwt ->
//                                        jwt.jwtAuthenticationConverter(jwtAuthenticationConverterWithAuthorities())
//                                )
//                )
               .oauth2ResourceServer(
                oauth2 ->
                        oauth2.jwt(
                                customizer ->
                                        customizer.jwtAuthenticationConverter(
                                                this.getTokenConverterWithValidation())))
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();

    }
    //https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/advanced.html#oauth2login-advanced-map-authorities-oauth2userservice
    //Extract roles from AccessToken for role_claim , Spring by default used scope or scp from AccessToken to pull Authorities
    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(final JwtDecoder jwtDecoder) {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            OidcUser oidcUser = delegate.loadUser(userRequest);
            OAuth2AccessToken accessToken = userRequest.getAccessToken();
            // 1) Fetch the authority information from the accessToken
            Jwt jwt = jwtDecoder.decode(accessToken.getTokenValue());
            JwtAuthenticationConverter jwtAuthenticationConverter = jwtAuthenticationConverterWithAuthorities();
            final AbstractAuthenticationToken abstTokenWithAuthorities = jwtAuthenticationConverter.convert(
                    jwt);
            // 2) Create a copy of oidcUser but use the Authorities
            oidcUser = new DefaultOidcUser(abstTokenWithAuthorities.getAuthorities(), oidcUser.getIdToken(), oidcUser.getUserInfo(),
                    name_claim);
            return oidcUser;
        };
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverterWithAuthorities() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        if(role_prefix!=null) grantedAuthoritiesConverter.setAuthorityPrefix(role_prefix);
        if(role_claim!=null) grantedAuthoritiesConverter.setAuthoritiesClaimName(role_claim);

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }
    public Converter<Jwt, AbstractAuthenticationToken> getTokenConverterWithValidation() {
        return jwt -> {
            final Map<String, Object> jwtClaims = jwt.getClaims();
            JwtAuthenticationConverter jwtAuthenticationConverter = jwtAuthenticationConverterWithAuthorities();
            final AbstractAuthenticationToken userAuthoritiesFromToken = jwtAuthenticationConverter.convert(
                    jwt);
            final Set<GrantedAuthority> authorities =
                    new HashSet<>(userAuthoritiesFromToken.getAuthorities());
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER"); 
            authorities.add(authority);
            return new JwtAuthenticationToken(jwt, authorities, (String) jwtClaims.get(name_claim));
        };
    }
    //https://docs.spring.io/spring-security/reference/reactive/oauth2/resource-server/jwt.html#webflux-oauth2resourceserver-validation-custom
    //Extra validation on AccessToken for aud/audience and iss/issuer
    @Bean
    JwtDecoder jwtDecoder() {
        final String getJwkSetUri = clientRegistrationRepository.findByRegistrationId(h2m_client_registration_id).getProviderDetails().getJwkSetUri();
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(getJwkSetUri).build();
        OAuth2TokenValidator<Jwt> withIssuer = getAcessTokenIssuerValidator();
        OAuth2TokenValidator<Jwt> withAudience = getAccessTokenAudValidator();
        final OAuth2TokenValidator<Jwt> validator = getAccessValidator(withIssuer, withAudience);
        if(validator!= null) jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }
    private OAuth2TokenValidator<Jwt> getAccessValidator(final OAuth2TokenValidator<Jwt> withIssuer,
            final OAuth2TokenValidator<Jwt> audienceValidator) {
        if (withIssuer != null && audienceValidator != null)
            return new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);
        if (audienceValidator != null)
            return new DelegatingOAuth2TokenValidator<>(audienceValidator);
        if (withIssuer != null)
            return new DelegatingOAuth2TokenValidator<>(withIssuer);
        return null;
    }
    private OAuth2TokenValidator<Jwt> getAccessTokenAudValidator() {
        if (access_token_aud != null) {
            return new AudienceValidator();
        }
        return null;
    }

    private  OAuth2TokenValidator<Jwt> getAcessTokenIssuerValidator() {
        String access_token_issuer = (String)clientRegistrationRepository.findByRegistrationId(h2m_client_registration_id).getProviderDetails().getConfigurationMetadata().get(access_token_issuer_config_metadata);
        if(access_token_issuer != null)
            return JwtValidators.createDefaultWithIssuer(access_token_issuer);
        else return null;
    }


    public class AudienceValidator implements OAuth2TokenValidator<Jwt> {
        OAuth2Error error = new OAuth2Error("invalid_token", "The required audience is missing", null);

        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            if (jwt.getAudience().contains(access_token_aud)) {
                return OAuth2TokenValidatorResult.success();
            } else {
                return OAuth2TokenValidatorResult.failure(error);
            }
        }
    }

    //https://docs.spring.io/spring-security/reference/servlet/oauth2/login/advanced.html#oauth2login-advanced-login-page
    /*
    The link’s destination for each OAuth Client defaults to the following:
    OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}"
     */
    public static String getLoginUrl(final String registrationId) {
        return OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI +"/" + registrationId;
    }


}