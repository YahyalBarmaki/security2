package com.security2.demo.models;

import lombok.Data;

import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @NotBlank
    @Size(max = 20)
    private String username;
    @NotBlank
    @Size(max = 20)
    @Email
    private String email;
    @NotBlank
    @Size(max = 120)
    private String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();

    public User() {
    }

    public User(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;

    }
}
