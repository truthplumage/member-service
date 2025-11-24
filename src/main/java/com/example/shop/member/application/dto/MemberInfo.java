package com.example.shop.member.application.dto;

import com.example.shop.member.domain.Member;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * 외부에 노출될 회원 정보를 표현하는 응답 DTO.
 * 도메인 엔티티 전체를 그대로 전달하지 않고 필요한 정보만 추려서 반환한다.
 */
public record MemberInfo(
        UUID id,
        String email,
        String name,
        String phone,
        String flag,
        LocalDateTime regDt,
        LocalDateTime modifyDt
) {

    public static MemberInfo from(Member member) {
        return new MemberInfo(
                member.getId(),
                member.getEmail(),
                member.getName(),
                member.getPhone(),
                member.getFlag(),
                member.getRegDt(),
                member.getModifyDt()
        );
    }
}
