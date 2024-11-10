package com.example.OAuth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login").permitAll() // Allow public access to home and static resources
                .anyRequest().authenticated()                                    // Secure other pages
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/profile", true)   // Redirect to profile page after successful login
            )
            .logout(logout -> logout
                .logoutUrl("/logout")  // URL for triggering logout
                .logoutSuccessUrl("/") // Redirect URL after successful logout
                .invalidateHttpSession(true) // Invalidate session
                .clearAuthentication(true) // Clear authentication
            );
        return http.build();
    }
}
