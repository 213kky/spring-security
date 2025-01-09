package com.example.springsecurity.security;

import com.example.springsecurity.common.BaseResponse;
import com.example.springsecurity.domain.Member;
import com.example.springsecurity.util.ResponseUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import static com.example.springsecurity.util.JwtUtil.*;

@Slf4j
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super("/api/login", authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {

        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            // body로 넘어온 값으로 member 객체를 생성
            Member member = new ObjectMapper().readValue(request.getReader(), Member.class);

            UsernamePasswordAuthenticationToken userToken =
                new UsernamePasswordAuthenticationToken(member.getEmail(), member.getPassword());

            this.setDetails(request, userToken);

            // AuthenticationManager에 인증을 위임
            return super.getAuthenticationManager().authenticate(userToken);
        }
    }

    // UsernamePasswordAuthenticationFilter 메소드와 동일
    private void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(super.authenticationDetailsSource.buildDetails(request));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        log.info("successfulAuthentication");
        // 1. 로그인 성공된 유저 조회
        Member member = ((CustomMemberDetails) authResult.getPrincipal()).getMember();

        String refreshToken = createRefreshToken(member);

        ResponseCookie refreshTokenCookie = generateRefreshTokenCookie(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        String accessToken = createAccessToken(member);

        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        ResponseUtil.createResponseBody(response, HttpStatus.OK);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                AuthenticationException failed) throws IOException, ServletException {
        log.info("unsuccessfulAuthentication");
        BaseResponse errorResponse = new BaseResponse(HttpStatus.BAD_REQUEST.value(), failed.getMessage());
        ResponseUtil.createResponseBody(response, errorResponse, HttpStatus.BAD_REQUEST);
    }
}
