package com.example.springsecurity.util;

import com.example.springsecurity.domain.Member;
import com.example.springsecurity.security.AuthProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;

@Slf4j
public class JwtUtil {

    private static final long SECOND = 1000;
    private static final long MINUTE = SECOND * 60;
    private static final long HOUR = MINUTE * 60;
    private static final long DAY = HOUR * 24;

    private static final long ACCESS_TOKEN_VALIDITY_TIME = 15 * MINUTE; // 15분
    private static final long REFRESH_TOKEN_VALIDITY_TIME = 12 * HOUR;  // 12시간

    public static String createAccessToken(Member member) {
        return Jwts.builder()
            .subject("accessToken")
            .claims(createAccessTokenClaims(member))
            .expiration(createTokenExpiration(ACCESS_TOKEN_VALIDITY_TIME))
            .signWith(createSigningKey(AuthProperties.getAccessSecret()))
            .compact();
    }

    public static String createRefreshToken(Member member) {
        return Jwts.builder()
            .subject("refreshToken")
            .claims(createRefreshTokenClaims(member))
            .expiration(createTokenExpiration(REFRESH_TOKEN_VALIDITY_TIME))
            .signWith(createSigningKey(AuthProperties.getRefreshSecret()))
            .compact();
    }

    public static ResponseCookie generateRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refresh", refreshToken)
            .httpOnly(true)
            .sameSite("None")
            .secure(true)
            .path("/")
            .maxAge(REFRESH_TOKEN_VALIDITY_TIME)
            .build();
    }

    private static Date createTokenExpiration(long expirationTime) {
        return new Date(System.currentTimeMillis() + expirationTime);
    }

    // BASE64로 인코딩된 문자열을 디코딩하여 대칭키를 생성한다. 이 키는 JWT 서명 과정에서 사용된다.
    public static Key createSigningKey(String base64EncodedSecretKey) {
        // 입력된 tokenSecret은 BASE64로 인코딩되어 있으므로, 먼저 디코딩하여 원래의 바이트 배열 형태로 복원한다.
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private static Map<String, Object> createAccessTokenClaims(Member member) {
        Map<String, Object> map = new HashMap<>();
        map.put("memberId", member.getId());
        map.put("memberEmail", member.getEmail());
        map.put("provider", member.getProvider());
        return map;
    }

    private static Map<String, Object> createRefreshTokenClaims(Member member) {
        Map<String, Object> map = new HashMap<>();
        map.put("memberEmail", member.getEmail());
        return map;
    }
}
