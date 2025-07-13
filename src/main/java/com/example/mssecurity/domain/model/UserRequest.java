package com.example.mssecurity.domain.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserRequest {
    private String username;
    private String email;
    private String password;
}
