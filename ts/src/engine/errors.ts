// Typed error hierarchy for the dorado container engine. Consumers can branch on
// these with instanceof. The messages are unchanged from the previous plain
// Error throws, and wrong-password and tampering deliberately share a single
// AuthError class and message so the two stay indistinguishable.

// Base class for every error this engine throws on bad input or auth failure.
export class DoradoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DoradoError";
    // Restore the prototype chain so instanceof works even when the compiled
    // output targets older runtimes that break Error subclassing.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Authentication failed: wrong password, corruption, or tampering. These cases
// are intentionally merged into one class and one message.
export class AuthError extends DoradoError {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

// The container is malformed or truncated: bad magic, unsupported version,
// unknown ids, truncated header or frame, oversized label, or a header chunk
// size that is structurally invalid.
export class MalformedContainerError extends DoradoError {
  constructor(message: string) {
    super(message);
    this.name = "MalformedContainerError";
  }
}

// Caller-supplied parameters are invalid: a bad chunk size on encrypt, hostile
// KDF cost, bad lengths, or malformed hex.
export class InvalidParamsError extends DoradoError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidParamsError";
  }
}
