-- ===================================================================
-- V4 - Assign scopes to roles
-- ===================================================================

-- ADMIN scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_ADMIN' AND s.name IN ('profile:read','profile:write','user:manage');

-- USER scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_USER' AND s.name = 'profile:read';
