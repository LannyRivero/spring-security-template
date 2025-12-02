package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.ChangePasswordTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.DevRegisterTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.LoginTransactionalAdapter;
import com.lanny.spring_security_template.infrastructure.adapter.usecase.transactional.RefreshTransactionalAdapter;

import lombok.RequiredArgsConstructor;

/**
 * <h1>AuthUseCaseImpl</h1>
 *
 * Primary application-layer orchestrator for the authentication subsystem.
 * This class provides the canonical implementation of {@link AuthUseCase}
 * following the principles of Clean Architecture:
 *
 * <ul>
 * <li>No dependency on Spring or infrastructure frameworks.</li>
 * <li>No logging, auditing, metrics, or cross-cutting concerns.</li>
 * <li>Delegates transactional boundaries to infrastructure adapters.</li>
 * <li>Pure orchestration of use-case logic.</li>
 * </ul>
 *
 * <h2>Responsibilities</h2>
 * <p>
 * AuthUseCaseImpl acts as a façade coordinating the different authentication
 * operations:
 * </p>
 *
 * <ul>
 * <li>{@code login} – credential validation and token issuance.</li>
 * <li>{@code refresh} – refresh token rotation or reuse.</li>
 * <li>{@code me} – retrieval of identity metadata (roles + scopes).</li>
 * <li>{@code registerDev} – developer / seed registration workflow.</li>
 * <li>{@code changePassword} – secure password update flow.</li>
 * </ul>
 *
 * <h2>Interaction Flow</h2>
 * <p>
 * Each method delegates the execution to its respective transactional adapter:
 * </p>
 *
 * <pre>
 * Controller  →  AuthUseCaseImpl  →  {Login/Refresh/Register/Password Adapters}  →  Application Services
 * </pre>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Stateless and deterministic.</li>
 * <li>Acts as the application boundary for REST controllers.</li>
 * <li>Perfectly mockable for unit tests.</li>
 * <li>Ensures minimal validation for input integrity.</li>
 * </ul>
 *
 * <h2>Not Included</h2>
 * <p>
 * This class intentionally avoids:
 * </p>
 *
 * <ul>
 * <li>Persistence logic</li>
 * <li>Security filters</li>
 * <li>Transaction management</li>
 * <li>Side-effects such as logging or auditing</li>
 * </ul>
 *
 * <p>
 * All cross-cutting concerns are handled externally by
 * {@code AuthUseCaseLoggingDecorator}, while persistence and transactions
 * are delegated to infrastructure-layer adapters.
 * </p>
 */
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final LoginTransactionalAdapter loginAdapter;
    private final RefreshTransactionalAdapter refreshAdapter;
    private final MeService meService;
    private final DevRegisterTransactionalAdapter devRegisterAdapter;
    private final ChangePasswordTransactionalAdapter changePasswordAdapter;

    @Override
    public JwtResult login(LoginCommand cmd) {
        validateInput(cmd.username(), cmd.password());
        return loginAdapter.login(cmd);
    }

    @Override
    public JwtResult refresh(RefreshCommand cmd) {
        return refreshAdapter.refresh(cmd);
    }

    @Override
    public MeResult me(MeQuery query) {
        return meService.me(query.username());
    }

    @Override
    public void registerDev(RegisterCommand cmd) {
        devRegisterAdapter.register(cmd);
    }

    @Override
    public void changePassword(String username, String oldPassword, String newPassword) {
        changePasswordAdapter.changePassword(username, oldPassword, newPassword);
    }

    /**
     * Performs minimal parameter validation to protect against malformed input.
     *
     * @param username the provided username
     * @param password the provided password
     * @throws IllegalArgumentException if either value is blank or null
     */
    private void validateInput(String username, String password) {
        if (username == null || username.isBlank() ||
                password == null || password.isBlank()) {
            throw new IllegalArgumentException("Username and password must not be blank");
        }
    }
}
