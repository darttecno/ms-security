package com.example.mssecurity.service;

import com.example.mssecurity.domain.entity.UserEntity;
import com.example.mssecurity.domain.model.AuthenticationRequest;
import com.example.mssecurity.domain.model.AuthenticationResponse;
import com.example.mssecurity.domain.model.UserRequest;
import com.example.mssecurity.domain.repository.UserRepository;
import com.example.mssecurity.exception.UserAlreadyExistsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtService jwtService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthenticationService authenticationService;

    private UserRequest userRequest;
    private UserEntity userEntity;
    private AuthenticationRequest authenticationRequest;

    @BeforeEach
    void setUp() {
        userRequest = UserRequest.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password")
                .build();

        userEntity = UserEntity.builder()
                .id(1L)
                .username("testuser")
                .email("test@example.com")
                .password("encodedPassword")
                .build();

        authenticationRequest = AuthenticationRequest.builder()
                .username("testuser")
                .password("password")
                .build();
    }

    @Test
    void register_Success() {
        when(userRepository.findByUsernameOrEmail(userRequest.getUsername(), userRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(userRequest.getPassword())).thenReturn("encodedPassword");
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);
        when(jwtService.generateToken(anyMap(), any(UserEntity.class))).thenReturn("jwtToken");

        AuthenticationResponse response = authenticationService.register(userRequest);

        assertNotNull(response);
        assertEquals("jwtToken", response.getToken());
        verify(userRepository, times(1)).findByUsernameOrEmail(userRequest.getUsername(), userRequest.getEmail());
        verify(passwordEncoder, times(1)).encode(userRequest.getPassword());
        verify(userRepository, times(1)).save(any(UserEntity.class));
        verify(jwtService, times(1)).generateToken(anyMap(), any(UserEntity.class));
    }

    @Test
    void register_UserAlreadyExistsException() {
        when(userRepository.findByUsernameOrEmail(userRequest.getUsername(), userRequest.getEmail())).thenReturn(Optional.of(userEntity));

        assertThrows(UserAlreadyExistsException.class, () -> authenticationService.register(userRequest));
        verify(userRepository, times(1)).findByUsernameOrEmail(userRequest.getUsername(), userRequest.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(UserEntity.class));
        verify(jwtService, never()).generateToken(anyMap(), any(UserEntity.class));
    }

    @Test
    void login_Success() {
        when(userRepository.findByUsernameOrEmail(authenticationRequest.getUsername(), authenticationRequest.getUsername())).thenReturn(Optional.of(userEntity));
        when(jwtService.generateToken(anyMap(), any(UserEntity.class))).thenReturn("jwtToken");

        AuthenticationResponse response = authenticationService.login(authenticationRequest);

        assertNotNull(response);
        assertEquals("jwtToken", response.getToken());
        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
        );
        verify(userRepository, times(1)).findByUsernameOrEmail(authenticationRequest.getUsername(), authenticationRequest.getUsername());
        verify(jwtService, times(1)).generateToken(anyMap(), any(UserEntity.class));
    }

    @Test
    void login_BadCredentialsException() {
        doThrow(new BadCredentialsException("Invalid credentials")).when(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
        );

        assertThrows(BadCredentialsException.class, () -> authenticationService.login(authenticationRequest));
        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
        );
        verify(userRepository, never()).findByUsernameOrEmail(anyString(), anyString());
        verify(jwtService, never()).generateToken(anyMap(), any(UserEntity.class));
    }

    @Test
    void login_UserNotFoundAfterAuthentication() {
        // Simulate successful authentication
        when(authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
        )).thenReturn(mock(UsernamePasswordAuthenticationToken.class));
        // Simulate user not found in repository after authentication
        when(userRepository.findByUsernameOrEmail(authenticationRequest.getUsername(), authenticationRequest.getUsername())).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> authenticationService.login(authenticationRequest));

        verify(authenticationManager, times(1)).authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
        );
        verify(userRepository, times(1)).findByUsernameOrEmail(authenticationRequest.getUsername(), authenticationRequest.getUsername());
        verify(jwtService, never()).generateToken(anyMap(), any(UserEntity.class));
    }
}
