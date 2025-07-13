package com.example.mssecurity.service;

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

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // Inyectado desde ApplicationConfig
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager; // Inyectado desde ApplicationConfig

    public AuthenticationResponse register(UserRequest request) {
        // 0. Comprobar si el usuario ya existe
        userRepository.findByUsername(request.getUsername()).ifPresent(user -> {
            throw new UserAlreadyExistsException("El nombre de usuario '" + user.getUsername() + "' ya está en uso.");
        });

        // 1. Crea un nuevo objeto UserEntity con los datos del request
        var user = new UserEntity();
        user.setUsername(request.getUsername());
        // 2. ¡MUY IMPORTANTE! Codifica la contraseña antes de guardarla
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        // 3. Guarda el nuevo usuario en la base de datos
        userRepository.save(user);
        // 4. Genera un token JWT para el nuevo usuario
        var jwtToken = jwtService.generateToken(user);
        // 5. Devuelve el token
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        // 1. Autentica al usuario con el gestor de Spring Security.
        //    Si las credenciales son incorrectas, lanzará una excepción automáticamente.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        // 2. Si la autenticación fue exitosa, busca al usuario en la base de datos
        var user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        // 3. Genera y devuelve un token para el usuario
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
