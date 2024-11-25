package com.example.springSecurity.security;

import com.google.common.collect.Sets;

import java.util.HashSet;
import java.util.Set;

import static com.example.springSecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(new HashSet<>()),
    ADMIN(Sets.newHashSet(STUDENT_READ,STUDENT_WRITE,COURSE_READ,COURSE_WRITE));

    private final Set<ApplicationUserPermission> permissions;


    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }
}
