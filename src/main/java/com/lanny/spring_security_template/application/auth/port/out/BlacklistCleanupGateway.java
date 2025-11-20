package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;
import java.util.List;

public interface BlacklistCleanupGateway {

    /**
     * Devuelve los JTIs de la blacklist que ya han expirado.
     */
    List<String> findExpired(Instant now);

    /**
     * Elimina un JTI de la blacklist.
     */
    void delete(String jti);
}
