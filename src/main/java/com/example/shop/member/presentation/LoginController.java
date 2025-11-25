package com.example.shop.member.presentation;

import com.example.shop.common.ResponseEntity;
import com.example.shop.member.application.MemberService;
import com.example.shop.member.presentation.dto.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
@RequiredArgsConstructor
public class LoginController {
    private final MemberService memberService;
    @PostMapping("${api.v1}/login")
    public ResponseEntity<HashMap<String, Object>> login(@RequestBody LoginRequest loginRequest){
        return memberService.login(loginRequest);
    }
    @GetMapping("${api.v1}/authorizations/check")
    public Boolean check(@RequestParam("httpMethod") String httpMethod, @RequestParam("requestPath") String requestPath){
        return memberService.check(httpMethod, requestPath);
    }
    @GetMapping("${api.v1}/refresh/token")
    public ResponseEntity<HashMap<String, Object>> refreshToken(@RequestHeader("refresh-token") String token){
        return memberService.refreshToken(token);
    }
}
