package com.example.shop.member.application;

import com.example.shop.common.ResponseEntity;
import com.example.shop.member.application.dto.MemberCommand;
import com.example.shop.member.application.dto.MemberInfo;
import com.example.shop.member.domain.Member;
import com.example.shop.member.domain.MemberRepository;
import com.example.shop.member.presentation.dto.LoginRequest;
import com.example.shop.member.util.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class MemberService {
    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtProvider jwtProvider;

    public ResponseEntity<List<MemberInfo>> findAll(Pageable pageable){
        Page<Member> page = memberRepository.findAll(pageable);
        List<MemberInfo> members = page.stream()
                .map(MemberInfo::from)
                .toList();
        return new ResponseEntity<>(HttpStatus.OK.value(), members, page.getTotalElements());
    }
    public ResponseEntity<MemberInfo> create(MemberCommand command) {
        String encodedPassword = passwordEncoder.encode(command.password());
        Member member = Member.create(
                command.email(),
                command.name(),
                encodedPassword,
                command.phone()
        );
        Member saved = memberRepository.save(member);
        return new ResponseEntity<>(HttpStatus.CREATED.value(), MemberInfo.from(saved), 1);
    }

    public ResponseEntity<MemberInfo> update(MemberCommand command, String id) {
        UUID uuid = UUID.fromString(id);
        Member member = memberRepository.findById(uuid)
                .orElseThrow(() -> new IllegalArgumentException("Member not found: " + id));
        String password = command.password();
        String encodedPassword = password == null || password.isBlank()
                ? member.getPassword()
                : passwordEncoder.encode(password);

        member.updateInformation(
                command.email(),
                command.name(),
                encodedPassword,
                command.phone()
        );

        Member updated = memberRepository.save(member);
        return new ResponseEntity<>(HttpStatus.OK.value(), MemberInfo.from(updated), 1);
    }

    public ResponseEntity<Void> delete(String id) {
        UUID uuid = UUID.fromString(id);
        memberRepository.deleteById(uuid);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT.value(), null, 0);
    }

    public ResponseEntity<HashMap<String, Object>> login(LoginRequest loginRequest) {
        Optional<Member> memberOptional = memberRepository.findByEmail(loginRequest.email());

        HashMap<String, Object> res = new HashMap<>();
        if(memberOptional.isPresent()){
            Member memeber = memberOptional.get();
            if(passwordEncoder.matches(loginRequest.password(), memeber.getPassword())){
                Authentication authentication = new UsernamePasswordAuthenticationToken(memeber.getId().toString(), null);
                String token = jwtProvider.generateToken(authentication);
                res.put("token", token);
                return new ResponseEntity<>(HttpStatus.OK.value(), res, 1);
            }else{
                throw new IllegalArgumentException("password is not correct");
            }
        }
        return null;
    }

    public Boolean check(String httpMethod, String requestPath) {
        return true;
    }
}
