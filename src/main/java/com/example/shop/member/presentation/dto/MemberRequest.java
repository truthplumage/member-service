package com.example.shop.member.presentation.dto;

import com.example.shop.member.application.dto.MemberCommand;

/**
 * HTTP 요청 페이로드를 표현하는 DTO.
 * presentation 계층에서만 사용되며, 애플리케이션 계층에는 {@link MemberCommand}로 변환해 전달한다.
 */
public record MemberRequest(
        String email,
        String name,
        String password,
        String phone
) {

    public MemberCommand toCommand() {
        return new MemberCommand(email, name, password, phone);
    }
}
