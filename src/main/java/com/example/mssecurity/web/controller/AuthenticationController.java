package com.example.mssecurity.web.controller;

import com.example.mssecurity.domain.model.AuthenticationRequest;
import com.example.mssecurity.domain.model.AuthenticationResponse;
import com.example.mssecurity.domain.model.UserRequest;
import com.example.mssecurity.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// Define que esta clase es un controlador REST
@RestController
// Todas las rutas en esta clase empezarán con /api/auth
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    // Endpoint para registrar un nuevo usuario
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserRequest request) {
        // Llama al servicio para procesar el registro y devuelve la respuesta
        return ResponseEntity.ok(authenticationService.register(request));
    }

    // Endpoint para iniciar sesión
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) {
        // Llama al servicio para procesar el login y devuelve la respuesta
        return ResponseEntity.ok(authenticationService.login(request));
    }
}
