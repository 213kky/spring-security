package com.example.springsecurity.dto;

import com.example.springsecurity.domain.Role;
import com.example.springsecurity.domain.Member;

public record SignUpRequest(
    String email,
    String password,
    String nickName,
    String name,
    Role role,
    String provider
) {

    public Member toMember() {
        return Member.builder()
                    .email(email)
                    .password(password)
                    .name(name)
                    .role(role)
                    .provider(provider)
                    .nickName(nickName)
                    .build();
    }
}
