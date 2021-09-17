package com.security2.demo.models;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@AllArgsConstructor
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer Id;
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    public Role() {

    }
}
