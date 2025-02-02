package com.example.springsecurity.service;

import com.example.springsecurity.domain.Member;
import com.example.springsecurity.dto.SignUpRequest;
import com.example.springsecurity.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public void signUp(SignUpRequest request) {
        String encodedPassword = passwordEncoder.encode(request.password());
        Member member = Member.builder()
                .email(request.email())
                .password(encodedPassword)
                .name(request.name())
                .role(request.role())
                .provider(request.provider())
                .nickName(request.nickName())
                .build();

        memberRepository.save(member);
    }

}
