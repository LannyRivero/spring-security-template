package com.lanny.spring_security_template.infrastructure.http;

import com.lanny.spring_security_template.infrastructure.security.ssrf.UrlSecurityValidator;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.MDC;
import java.util.Objects;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * HTTP client infrastructure configuration.
 *
 * Responsibilities:
 * - Configure Apache HttpClient (pooling, timeouts)
 * - Expose RestTemplate for outbound calls
 * - Register SSRF protection via UrlSecurityValidator
 * - Propagate correlation-id headers
 */
@Configuration
@EnableConfigurationProperties(HttpClientProperties.class)
public class HttpClientConfig {

    // --------------------------------------------------
    // SSRF / Outbound URL validation
    // --------------------------------------------------

    @Bean
    public UrlSecurityValidator urlSecurityValidator() {
        return new UrlSecurityValidator();
    }

    // --------------------------------------------------
    // RestTemplate (Apache HttpClient based)
    // --------------------------------------------------

    @Bean
    public RestTemplate restTemplate(HttpClientProperties props) {

        ConnectionConfig connectionConfig = ConnectionConfig.custom()
                .setConnectTimeout(Timeout.of(props.connectTimeout()))
                .build();

        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
        cm.setDefaultConnectionConfig(connectionConfig);
        cm.setMaxTotal(props.maxTotalConnections());
        cm.setDefaultMaxPerRoute(props.maxConnectionsPerRoute());

        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.of(props.readTimeout()))
                .setConnectionRequestTimeout(Timeout.of(props.requestTimeout()))
                .build();

        HttpClient httpClient = HttpClients.custom()
                .setConnectionManager(cm)
                .setDefaultRequestConfig(requestConfig)
                .disableAutomaticRetries()
                .build();

        RestTemplate rt = new RestTemplate(
                new HttpComponentsClientHttpRequestFactory(Objects.requireNonNull(httpClient)));

        rt.getInterceptors().add((request, body, execution) -> {
            if (props.propagateCorrelationId()) {
                String cid = MDC.get("correlationId");
                String headerName = props.correlationHeaderName();
                if (cid != null && !cid.isBlank() && headerName != null) {
                    request.getHeaders().add(headerName, cid);
                }
            }
            return execution.execute(request, body);
        });

        return rt;
    }
}
