package com.alleato.dorado.engine;

import java.io.IOException;

/**
 * Thrown for a malformed, unsupported, or failed-authentication container: bad
 * magic or version, truncation, hostile KDF parameters, a label mismatch, or a MAC
 * verification failure. It extends {@link IOException} so a caller can catch all
 * stream errors uniformly, or catch this to distinguish a bad container from an
 * underlying disk or network error.
 *
 * <p>Two subtypes refine this: {@link AuthenticationException} for a MAC failure
 * (wrong password, corruption, or tampering, all merged) and {@link
 * MalformedContainerException} for a structurally invalid container. Catch this
 * parent to treat any bad container uniformly.
 */
public class DoradoException extends IOException {
    public DoradoException(String message) {
        super(message);
    }
}
