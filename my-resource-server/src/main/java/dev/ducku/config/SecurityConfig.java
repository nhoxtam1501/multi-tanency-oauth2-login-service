package dev.ducku.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomJwtConverter customJwtConverter;

    @Value("${jwkUri}")
    private String jwkUri;

    @Value("${opaque.resource.server.client.id}")
    private String opaqueClientId;

    @Value("${opaque.resource.server.client.secret}")
    private String opaqueClientSecret;

    @Value("${opaque.resource.server.introspect.uri}")
    private String opaqueIntrospectUri;


    public SecurityConfig(CustomJwtConverter customJwtConverter) {
        this.customJwtConverter = customJwtConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.oauth2ResourceServer(resourceConfigure -> {

            resourceConfigure.authenticationManagerResolver(authenticationManagerResolver(jwtDecoder(), opaqueTokenIntrospector(), customJwtConverter)); //only all of AS are using none opaque token(jwt) it will work
            /*resourceConfigure.jwt(j -> j.jwkSetUri(jwkUri).jwtAuthenticationConverter(customJwtConverter)); //JWT TOKEN 🎫
             */
            /*resourceConfigure.opaqueToken(o -> o.introspectionUri(opaqueIntrospectUri)  //OPAQUE TOKEN 🎟️
                    .introspectionClientCredentials(opaqueClientId, opaqueClientSecret));
*/
        });

        http.authorizeHttpRequests(request -> request.anyRequest().authenticated());

        return http.build();
    }


    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(JwtDecoder jwtDecoder, OpaqueTokenIntrospector opaqueTokenIntrospector, CustomJwtConverter customJwtConverter) {
        //if all AS use none opaque token(JWT)
       /* JwtIssuerAuthenticationManagerResolver a = JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers("http://localhost:8080", "http://localhost:7070");
        return a; */
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        jwtAuthenticationProvider.setJwtAuthenticationConverter(customJwtConverter);
        AuthenticationManager jwtAuth = new ProviderManager(jwtAuthenticationProvider);

        AuthenticationManager opaqueAuth = new ProviderManager(new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector));
        return (request) -> {
            if ("jwt".equals(request.getHeader("type"))) {
                return jwtAuth;
            } else {
                return opaqueAuth;
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(jwkUri).build();
    }

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {
        return new SpringOpaqueTokenIntrospector(opaqueIntrospectUri, opaqueClientId, opaqueClientSecret);
    }
}
