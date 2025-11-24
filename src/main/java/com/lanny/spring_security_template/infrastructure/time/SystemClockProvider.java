package com.lanny.spring_security_template.infrastructure.time;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Clock;

/**
 * Real clock used in production environments.
 */
@Component
@Profile({"dev", "prod"})
public class SystemClockProvider implements ClockProvider {

    private final Clock clock = Clock.systemUTC();

    @Override
    public Clock clock() {
        return clock;
    }
}
