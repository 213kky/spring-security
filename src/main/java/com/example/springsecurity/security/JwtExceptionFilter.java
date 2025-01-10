package com.example.springsecurity.security;

import com.example.springsecurity.common.BaseErrorResponse;
import com.example.springsecurity.util.ResponseUtil;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("JwtExceptionFilter");
        try {
            filterChain.doFilter(request, response);
        } catch (SignatureException e){
            log.info("SignatureException");
            ResponseUtil.createResponseBody(response, new BaseErrorResponse(e.getMessage()), HttpStatus.UNAUTHORIZED);
        } catch (JwtException e) {
            ResponseUtil.createResponseBody(response, new BaseErrorResponse(e.getMessage()), HttpStatus.UNAUTHORIZED);
        }
    }
}
