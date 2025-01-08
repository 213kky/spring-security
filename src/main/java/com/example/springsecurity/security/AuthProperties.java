package com.example.springsecurity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AuthProperties {

    private static String accessSecret;
    private static String refreshSecret;

    @Value("${jwt.secret.access}")
    private void setAccessSecret(String accessSecret) {
        this.accessSecret = accessSecret;
    }

    public static String getAccessSecret() {
        return accessSecret;
    }

    @Value("${jwt.secret.refresh}")
    private void setRefreshSecret(String refreshSecret) {
        this.refreshSecret = refreshSecret;
    }

    public static String getRefreshSecret() {
        return refreshSecret;
    }
}
