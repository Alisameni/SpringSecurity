package com.example.springSecurity.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.springSecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(new HashSet<>()),
    ADMIN(Sets.newHashSet(STUDENT_READ,STUDENT_WRITE,COURSE_READ,COURSE_WRITE)),
    ADMINTRAINEE(Sets.newHashSet(STUDENT_READ,COURSE_READ));

    private final Set<ApplicationUserPermission> permissions;


    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthority() {
         Set<SimpleGrantedAuthority> permissions = getPermissions()
                .stream().map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
         permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
         return permissions;
    }
}
