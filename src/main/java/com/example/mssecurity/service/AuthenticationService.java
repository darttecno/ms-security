package com.example.mssecurity.service;

import aj.org.objectweb.asm.commons.Remapper;
import com.example.mssecurity.domain.entity.UserEntity;
import com.example.mssecurity.domain.model.AuthenticationRequest;
import com.example.mssecurity.domain.model.AuthenticationResponse;
import com.example.mssecurity.domain.model.UserRequest;
import com.example.mssecurity.domain.repository.UserRepository;
import com.example.mssecurity.exception.UserAlreadyExistsException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(UserRequest request) {
        userRepository.findByUsernameOrEmail(request.getUsername(), request.getEmail()).ifPresent(user -> {
            throw new UserAlreadyExistsException("El username '" + request.getUsername() + "' o el email '" + request.getEmail() + "' ya están en uso.");
        });

        var user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        
        // <-- CAMBIO: Guarda el usuario y obtén la instancia con el ID asignado por la BD
        var savedUser = userRepository.save(user);

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", savedUser.getId());

        var jwtToken = jwtService.generateToken(extraClaims, savedUser);
        var refreshToken = jwtService.generateRefreshToken(savedUser);

        savedUser.getRefreshTokens().add(refreshToken);
        userRepository.save(savedUser);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        
        var user = userRepository.findByUsernameOrEmail(request.getUsername(), request.getUsername()).orElseThrow();

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());

        var jwtToken = jwtService.generateToken(extraClaims, user);
        var refreshToken = jwtService.generateRefreshToken(user);

        user.getRefreshTokens().add(refreshToken);
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Optional<UserEntity> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }

    public List<UserEntity> getAuthenticatedUsers() {
        return userRepository.findByRefreshTokensIsNotEmpty();
    }

    public AuthenticationResponse refreshToken(String refreshToken) {
        final String username = jwtService.extractUsername(refreshToken);
        UserEntity user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (jwtService.isRefreshTokenValid(refreshToken, user) && user.getRefreshTokens().contains(refreshToken)) {
            // Invalida el refresh token antiguo
            user.getRefreshTokens().remove(refreshToken);

            // Genera nuevos tokens
            Map<String, Object> extraClaims = new HashMap<>();
            extraClaims.put("userId", user.getId());
            var newAccessToken = jwtService.generateToken(extraClaims, user);
            var newRefreshToken = jwtService.generateRefreshToken(user);

            // Guarda el nuevo refresh token
            user.getRefreshTokens().add(newRefreshToken);
            userRepository.save(user);

            return AuthenticationResponse.builder()
                    .token(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();
        } else {
            throw new RuntimeException("Invalid Refresh Token");
        }
    }

    public void logout(String refreshToken) {
        final String username = jwtService.extractUsername(refreshToken);
        UserEntity user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getRefreshTokens().contains(refreshToken)) {
            user.getRefreshTokens().remove(refreshToken);
            userRepository.save(user);
        } else {
            throw new RuntimeException("Refresh Token not found for user");
        }
    }
}