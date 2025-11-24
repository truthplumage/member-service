package com.example.shop.member.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtProvider {
    @Value("${token.maker}")
    private String tokenSecret;
    @Value("${token.public}")
    private String tokenPublic;
    @Value("${token.private}")
    private String tokenPrivate;

    private static final long JWT_EXPIRATION_MS = 86400000L * 7;

    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expireDate = new Date(now.getTime() + JWT_EXPIRATION_MS);
        log.info("tokenSecret {}", tokenSecret);
        return Jwts.builder().subject((String) authentication.getPrincipal())
                .issuedAt(now)
                .expiration(expireDate)
                .signWith(loadPrivateKey(tokenPrivate), Jwts.SIG.RS256)
//                .signWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(tokenSecret)), Jwts.SIG.HS512)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
//                    .verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(tokenSecret)))
                    .verifyWith(loadPublicKey(tokenPublic))
                    .build().parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException expiredJwtException) {
            expiredJwtException.printStackTrace();
            log.error(expiredJwtException.getMessage());
            throw new JwtException("Expired");
        } catch (JwtException jwtException) {
            jwtException.printStackTrace();
            log.error(jwtException.getMessage());
            throw new JwtException("JWT error");
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage());
        }
    }

    public String getUserDataFromJwt(String token) {
        try {
            return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(Base64.getDecoder().decode(tokenPublic))).build().parseSignedClaims(token).getPayload().getSubject();
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtException("Expired");
        } catch (JwtException jwtException) {
            throw new JwtException("JWT error");
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage());
        }
    }

    public KeyPair makeRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair pa = keyPairGenerator.generateKeyPair();
            String privateKey = new String(Base64.getEncoder().encode(pa.getPrivate().getEncoded()));
            String publicKey = new String(Base64.getEncoder().encode(pa.getPublic().getEncoded()));
            log.info("private key : {}", privateKey);
            log.info("public key : {}", publicKey);
            return pa;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    private PrivateKey loadPrivateKey(String tokenPrivate) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(tokenPrivate);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid private key", e);
        }
    }

    private PublicKey loadPublicKey(String tokenPublic) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(tokenPublic);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid public key", e);
        }
    }
}
