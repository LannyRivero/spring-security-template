-- ===================================================================
-- V100 - Development users
-- ===================================================================

INSERT INTO users (id, username, email, password_hash, enabled, status)
VALUES
(UUID(), 'admin', 'admin@example.com', '{noop}admin123', TRUE, 'ACTIVE'),
(UUID(), 'user', 'user@example.com', '{noop}user123', TRUE, 'ACTIVE');

-- Assign roles

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ROLE_ADMIN';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'user' AND r.name = 'ROLE_USER';
