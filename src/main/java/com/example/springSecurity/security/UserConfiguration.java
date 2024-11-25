package com.example.springSecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.springSecurity.security.ApplicationUserRole.ADMIN;
import static com.example.springSecurity.security.ApplicationUserRole.STUDENT;

@Configuration
public class UserConfiguration {

    private final PasswordEncoder passwordEncoder;

    public UserConfiguration(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    @Bean
    public UserDetailsService userDetailsService() {
        var annasmithUser  = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()).build();

        var lindaUser  = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name()).build();

        return new InMemoryUserDetailsManager(annasmithUser,lindaUser);
    }
}
