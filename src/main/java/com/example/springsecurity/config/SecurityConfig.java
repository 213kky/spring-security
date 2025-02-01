package com.example.springsecurity.config;

import com.example.springsecurity.repository.MemberRepository;
import com.example.springsecurity.security.CustomAuthenticationEntryPoint;
import com.example.springsecurity.security.CustomLogoutHandler;
import com.example.springsecurity.security.JwtAuthenticationFilter;
import com.example.springsecurity.security.CustomMemberDetailsService;
import com.example.springsecurity.security.JwtAuthenticationProvider;
import com.example.springsecurity.security.JwtAuthorizationFilter;
import com.example.springsecurity.security.JwtExceptionFilter;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomMemberDetailsService customMemberDetailsService;
    private final MemberRepository memberRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager());
        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(memberRepository);

        http
            .csrf(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(config -> config.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http
            .logout(logout -> logout
                .logoutUrl("/api/logout")
                .logoutSuccessUrl("/api")
                .addLogoutHandler(new CustomLogoutHandler())
                .deleteCookies("refresh") // 쿠키삭제 핸들러 추가 코드
            );

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/login", "/api/signup").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/mail/certification-code/send").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/mail/certification-code/verify").permitAll()
                .anyRequest().denyAll()
            );
        http
            .exceptionHandling(handler -> handler
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
            );

        http
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(jwtAuthorizationFilter, JwtAuthenticationFilter.class)
            .addFilterBefore(new JwtExceptionFilter(), LogoutFilter.class); // LogoutFilter 필터가 JwtAuthorizationFilter 필터보다 앞에 있는데 오류 나면 못잡아서 수정

        return http.build();
    }

    @Bean // 다중 AuthenticationProvider 등록가능
    public AuthenticationManager authenticationManager() throws Exception {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
        authenticationProviders.add(new JwtAuthenticationProvider(customMemberDetailsService, passwordEncoder()));

        return new ProviderManager(authenticationProviders);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(
            List.of("http://localhost:3000")
        );
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(1800L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
