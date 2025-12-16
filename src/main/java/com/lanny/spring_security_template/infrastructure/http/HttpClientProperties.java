package com.lanny.spring_security_template.infrastructure.http;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties(prefix = "http.client")
public record HttpClientProperties(

                @NotNull @DefaultValue("PT3S") Duration connectTimeout,
                @NotNull @DefaultValue("PT5S") Duration readTimeout,
                @NotNull @DefaultValue("PT2S") Duration requestTimeout,

                @Min(1) @DefaultValue("50") int maxTotalConnections,
                @Min(1) @DefaultValue("20") int maxConnectionsPerRoute,

                @DefaultValue("true") boolean propagateCorrelationId,
                @DefaultValue("X-Correlation-Id") @NotBlank String correlationHeaderName

) {

        public HttpClientProperties {
                if (requestTimeout.compareTo(connectTimeout) < 0) {
                        throw new IllegalArgumentException(
                                        "requestTimeout must be >= connectTimeout");
                }
        }
}
