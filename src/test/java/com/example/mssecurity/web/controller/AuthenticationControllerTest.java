package com.example.mssecurity.web.controller;

import com.example.mssecurity.domain.entity.UserEntity;
import com.example.mssecurity.domain.model.AuthenticationRequest;
import com.example.mssecurity.domain.model.AuthenticationResponse;
import com.example.mssecurity.domain.model.UserRequest;
import com.example.mssecurity.service.AuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AuthenticationController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class AuthenticationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationService authenticationService;

    @MockBean
    private com.example.mssecurity.service.JwtService jwtService;

    @MockBean
    private org.springframework.security.core.userdetails.UserDetailsService userDetailsService;

    @Autowired
    private ObjectMapper objectMapper;

    private UserRequest userRequest;
    private AuthenticationRequest authenticationRequest;
    private AuthenticationResponse authenticationResponse;
    private UserEntity userEntity;

    @BeforeEach
    void setUp() {
        userRequest = UserRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password")
                .build();

        authenticationRequest = AuthenticationRequest.builder()
                .username("testuser")
                .password("password")
                .build();

        authenticationResponse = AuthenticationResponse.builder()
                .token("jwt_token")
                .build();

        userEntity = UserEntity.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .build();
    }

    @Test
    void register_Success() throws Exception {
        when(authenticationService.register(any(UserRequest.class))).thenReturn(authenticationResponse);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(userRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt_token"));
    }

    @Test
    void login_Success() throws Exception {
        when(authenticationService.login(any(AuthenticationRequest.class))).thenReturn(authenticationResponse);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(authenticationRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt_token"));
    }

    @Test
    void getUsers_AllUsers() throws Exception {
        when(authenticationService.getAllUsers()).thenReturn(Arrays.asList(userEntity));

        mockMvc.perform(get("/api/auth/users"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").value("testuser"));
    }

    @Test
    void getUsers_UserById_Found() throws Exception {
        when(authenticationService.getUserById(1L)).thenReturn(Optional.of(userEntity));

        mockMvc.perform(get("/api/auth/users")
                        .param("id", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void getUsers_UserById_NotFound() throws Exception {
        when(authenticationService.getUserById(2L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/auth/users")
                        .param("id", "2"))
                .andExpect(status().isNotFound());
    }
}
