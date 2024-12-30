package com.example.springsecurity.repository;

import com.example.springsecurity.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {

}
