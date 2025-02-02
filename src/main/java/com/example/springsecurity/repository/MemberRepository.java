package com.example.springsecurity.repository;

import com.example.springsecurity.domain.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmailAndProvider(String email, String provider);
    boolean existsByEmail(String email);
}
