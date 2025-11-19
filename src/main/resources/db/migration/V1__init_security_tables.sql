-- ===================================================================
-- V1 - Core security tables
-- ===================================================================

CREATE TABLE roles (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE scopes (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE users (
    id              VARCHAR(36) PRIMARY KEY,
    username        VARCHAR(50) NOT NULL UNIQUE,
    email           VARCHAR(100) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    status          VARCHAR(20) DEFAULT 'ACTIVE'
);

CREATE TABLE user_roles (
    user_id     VARCHAR(36) NOT NULL,
    role_id     VARCHAR(36) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE role_scopes (
    role_id     VARCHAR(36) NOT NULL,
    scope_id    VARCHAR(36) NOT NULL,
    PRIMARY KEY (role_id, scope_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (scope_id) REFERENCES scopes(id)
);
