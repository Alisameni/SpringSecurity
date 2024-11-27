package com.example.springSecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;

import static com.example.springSecurity.security.ApplicationUserPermission.*;
import static com.example.springSecurity.security.ApplicationUserRole.*;
import static com.example.springSecurity.security.ApplicationUserRole.ADMINTRAINEE;
import static com.example.springSecurity.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/css/*", "/js/*").permitAll()
                        .requestMatchers("/api/**").hasRole(STUDENT.name())
                        .anyRequest()
                        .authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                        .defaultSuccessUrl("/home",true))
                .rememberMe(rememberMe -> rememberMe
                        .key("This is very HOT!")
                        .tokenValiditySeconds(7 * 24 * 60 * 60))
                .logout(logout ->logout
                        .logoutUrl("/logout")
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/login","GET"))
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID", "remember-me")
                        .logoutSuccessUrl("/login"));
        return http.build();
    }
}
