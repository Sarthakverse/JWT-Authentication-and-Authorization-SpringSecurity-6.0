package com.signupandlogin.jwtauthentication.configuration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()

                //let us permit all white points(that don't need jwt authentication...fo eg: registration)
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()

                .anyRequest() //all the other request has to be authenticated
                .authenticated()

                .and() // now we also don't want to store the session information, so make it stateless
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //so for each request a new session gets created

                .and()// now we need to tell spring which authentication provider we are using
                .authenticationProvider(authenticationProvider)

                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);// now we will use filter before username-password authentication filter


        return http.build();
    }
}
