package com.lanny.spring_security_template.application.auth.policy;

import java.time.Duration;

public interface TokenPolicyProperties {

    Duration accessTokenTtl();

    Duration refreshTokenTtl();

    String issuer();

    String accessAudience();

    String refreshAudience();

}
