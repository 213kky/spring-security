package com.example.springsecurity.service;

import com.example.springsecurity.dto.SignUpRequest;
import com.example.springsecurity.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public void signUp(SignUpRequest request) {
        memberRepository.save(request.toMember());
    }

}
