package com.example.springsecurity.util;

import static com.example.springsecurity.util.JwtUtil.createSigningKey;

import com.example.springsecurity.security.AuthProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import javax.crypto.SecretKey;

public class AccessTokenUtil {

    public static Claims getClaimsFromAccessToken(String accessToken) {
        return Jwts.parser().verifyWith((SecretKey) createSigningKey(AuthProperties.getAccessSecret())).build().parseSignedClaims(accessToken).getPayload();
    }

    public static String extractAccessTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7).trim();
        }
        return null;
    }
}
