package com.example.springSecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

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
                        .requestMatchers("/", "index.html", "/css/*", "/js/*").permitAll()
                        .requestMatchers("/api/**").hasRole(STUDENT.name())
                        //requestMatcher is one of the way  to implement permission based authentication
                        //another way to implement permission based authentication is use of @PreAuthorize in controller
//                        .requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                        .requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
                        .anyRequest()
                        .authenticated())
                .httpBasic();
        return http.build();
    }
}
