package com.alleato.dorado.engine;

/**
 * Thrown when a container frame fails MAC verification. This single failure path is
 * shared by a wrong password, corruption, and deliberate tampering: they are
 * deliberately indistinguishable (same type and same message) so an attacker cannot
 * tell which of those occurred. It extends {@link DoradoException} so callers that
 * only care about "bad container" can still catch the parent.
 */
public class AuthenticationException extends DoradoException {
    public AuthenticationException(String message) {
        super(message);
    }
}
