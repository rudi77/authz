/** Errors raised by the SDK. */

export class AuthzClientError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuthzClientError";
  }
}

export class AuthzServiceError extends AuthzClientError {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`AuthZ service returned ${status}: ${JSON.stringify(body)}`);
    this.name = "AuthzServiceError";
  }
}

export class PermissionDeniedError extends AuthzClientError {
  constructor(public readonly permission: string) {
    super(`Permission denied: ${permission}`);
    this.name = "PermissionDeniedError";
  }
}
