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
        
        // <-- CAMBIO: Prepara los claims (datos extra) para el token
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", savedUser.getId());
        
        // <-- CAMBIO: Genera el token pasando los claims extra
        var jwtToken = jwtService.generateToken(extraClaims, savedUser);
        
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getLogin(),
                        request.getPassword()
                )
        );
        
        var user = userRepository.findByUsernameOrEmail(request.getLogin(), request.getLogin()).orElseThrow();
        
        // <-- CAMBIO: Prepara los claims (datos extra) para el token
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());
        
        // <-- CAMBIO: Genera el token pasando los claims extra
        var jwtToken = jwtService.generateToken(extraClaims, user);
        
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public Optional<UserEntity> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public List<UserEntity> getAllUsers() {
        return userRepository.findAll();
    }
}