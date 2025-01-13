package com.example.springsecurity.security;

import com.example.springsecurity.util.AccessTokenUtil;
import com.example.springsecurity.util.ResponseUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

    // 로그아웃 이전에 JwtAuthorizationFilter를 거쳐서,
    // 엑세스토큰 검증하고 없으면 리프레시 토큰으로 엑세스 발급해서 authentication를 context에 저장하는 로직을 거쳐 해당 메소드에서 authentication를 사용하는 것 보다,
    // 직접 토큰만 검증하는 방식이 낫다고 판단
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        log.info("logout");
        String accessToken = AccessTokenUtil.extractAccessTokenFromRequest(request);

        try {
            AccessTokenUtil.getClaimsFromAccessToken(accessToken); // 검증
        } catch (ExpiredJwtException e) { // 엑세스 토큰 만료, 리프레시만 지우면 됨 -> SecurityConfig에서 리프레시 쿠키삭제 설정함
            ResponseUtil.createResponseBody(response, HttpStatus.OK);
        }
    }
}
