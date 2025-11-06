package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "scopes")
@Getter
@Setter
@NoArgsConstructor
public class ScopeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    @ManyToMany(mappedBy = "scopes")
    private Set<UserEntity> users = new HashSet<>();

    public ScopeEntity(String name) {
        this.name = name;
    }
}

