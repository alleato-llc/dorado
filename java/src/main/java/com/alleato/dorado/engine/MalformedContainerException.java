package com.alleato.dorado.engine;

/**
 * Thrown for a structurally invalid container: bad magic, an unsupported version, a
 * truncated header or frame, an invalid frame flag, an oversized frame, an unknown
 * KDF/MAC/PRF id, hostile KDF cost parameters, a too-long label, an invalid header
 * chunk size, or a label mismatch. It extends {@link DoradoException} so callers that
 * only care about "bad container" can still catch the parent, while those that want to
 * separate a malformed file from a failed authentication can catch this directly.
 */
public class MalformedContainerException extends DoradoException {
    public MalformedContainerException(String message) {
        super(message);
    }
}
