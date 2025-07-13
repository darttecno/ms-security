package com.example.mssecurity.service;

import com.example.mssecurity.domain.entity.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    private String secretKey;
    private UserEntity userEntity;

    @BeforeEach
    void setUp() {
        secretKey = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970"; // Ejemplo de clave secreta
        ReflectionTestUtils.setField(jwtService, "secretKey", secretKey);

        userEntity = UserEntity.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("password")
                .build();
    }

    private String generateTestToken(UserEntity userEntity, long expirationTimeMillis) {
        return Jwts
                .builder()
                .setClaims(new HashMap<>())
                .setSubject(userEntity.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTimeMillis))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Test
    void extractUsername_ValidToken() {
        String token = generateTestToken(userEntity, 1000 * 60 * 24); // 24 horas
        String username = jwtService.extractUsername(token);
        assertEquals(userEntity.getUsername(), username);
    }

    @Test
    void generateToken_UserEntity() {
        String token = jwtService.generateToken(userEntity);
        assertNotNull(token);
        assertEquals(userEntity.getUsername(), jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, userEntity));
    }

    @Test
    void generateToken_ExtraClaimsAndUserEntity() {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", "ADMIN");
        String token = jwtService.generateToken(extraClaims, userEntity);
        assertNotNull(token);
        assertEquals(userEntity.getUsername(), jwtService.extractUsername(token));
        assertTrue(jwtService.isTokenValid(token, userEntity));

        Claims claims = ReflectionTestUtils.invokeMethod(jwtService, "extractAllClaims", token, getSigningKey());
        assertEquals("ADMIN", claims.get("role"));
    }

    @Test
    void isTokenValid_ValidToken() {
        String token = generateTestToken(userEntity, 1000 * 60 * 24);
        assertTrue(jwtService.isTokenValid(token, userEntity));
    }

    @Test
    void isTokenValid_InvalidToken_WrongUsername() {
        UserEntity anotherUser = UserEntity.builder().username("anotheruser").build();
        String token = generateTestToken(userEntity, 1000 * 60 * 24);
        assertFalse(jwtService.isTokenValid(token, anotherUser));
    }

    @Test
    void isTokenValid_ExpiredToken() {
        String expiredToken = generateTestToken(userEntity, -1000); // Token expirado
        assertFalse(jwtService.isTokenValid(expiredToken, userEntity));
    }

    @Test
    void isTokenValid_TokenWithDifferentSignature() {
        String anotherSecretKey = "50645367566B5970337336763979244226452948404D635166546A576E5A7234"; // Otra clave secreta válida en Base64
        Key anotherSigningKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(anotherSecretKey));

        String tokenWithDifferentSignature = Jwts
                .builder()
                .setClaims(new HashMap<>())
                .setSubject(userEntity.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(anotherSigningKey, SignatureAlgorithm.HS256)
                .compact();

        assertFalse(jwtService.isTokenValid(tokenWithDifferentSignature, userEntity));
    }
}
