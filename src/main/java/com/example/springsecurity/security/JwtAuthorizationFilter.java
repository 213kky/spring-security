package com.example.springsecurity.security;

import com.example.springsecurity.domain.Member;
import com.example.springsecurity.repository.MemberRepository;
import com.example.springsecurity.util.ResponseUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static com.example.springsecurity.util.AccessTokenUtil.extractAccessTokenFromRequest;
import static com.example.springsecurity.util.AccessTokenUtil.getClaimsFromAccessToken;
import static com.example.springsecurity.util.JwtUtil.createAccessToken;
import static com.example.springsecurity.util.RefreshTokenUtil.checkIfRefreshTokenValid;
import static com.example.springsecurity.util.RefreshTokenUtil.extractRefreshTokenFromCookies;

@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final MemberRepository memberRepository;

    public JwtAuthorizationFilter(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    // 1. RequestHeader 안의 엑세스 토큰 확인
    // 2. 액세스토큰이 유효하다면 -> 인증된 객체 저장하고 doFilter 수행

    private static final List<RequestMatcher> excludedUrlPatterns = Arrays.asList( // 필터 적용 안할 url 지정
        new AntPathRequestMatcher("/api/login", "POST")
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.info("AuthorizationFilter");
        if (isExcludedUrl(request)) {
            filterChain.doFilter(request, response); // 필터 스킵, 다음 필터 실행.
            return;
        }

        String accessToken = extractAccessTokenFromRequest(request);

        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        Claims claims = null;
        Member member = null;

        try {
            claims = getClaimsFromAccessToken(accessToken);
        } catch (ExpiredJwtException e) {
            // 엑세스 토큰이 만료되었을 때 리프레시 토큰이 유효하다면, 엑세스 토큰을 새로 발급해줍니다.
            String refreshToken = extractRefreshTokenFromCookies(request);

            if (!checkIfRefreshTokenValid(refreshToken)) {
                ResponseUtil.createResponseBody(response, "access-token expired, refresh-token is invalid", HttpStatus.UNAUTHORIZED);
                return;
            }

            claims = e.getClaims(); // 엑세스 토큰 claims

            Long memberId = ((Integer) claims.get("memberId")).longValue();
            member = memberRepository.findById(memberId).orElseThrow();

            String newAccessToken = createAccessToken(member);

            response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newAccessToken);
        }

        if(member == null) {
            member = findMemberFromAccessTokenClaims(response, claims);
        }

        this.saveAuthenticationToSecurityContextHolder(member);

        filterChain.doFilter(request, response);
    }

    private Member findMemberFromAccessTokenClaims(HttpServletResponse response, Claims claims) throws IOException {
        return memberRepository.findByEmailAndProvider(
            claims.get("memberEmail").toString(),
            claims.get("provider").toString()
        ).orElseGet(() -> {
            ResponseUtil.createResponseBody(response, HttpStatus.UNAUTHORIZED);
            return null;
        });
    }

    private void saveAuthenticationToSecurityContextHolder(Member member) {
        CustomMemberDetails memberDetails = new CustomMemberDetails(member);

        // 인가 처리가 정상적으로 완료된다면 Authentication 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            memberDetails, null, memberDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean isExcludedUrl(HttpServletRequest request) {
        return excludedUrlPatterns.stream().anyMatch(pattern -> pattern.matches(request));
    }
}
