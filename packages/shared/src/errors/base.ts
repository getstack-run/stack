export class StackError extends Error {
  /**
   * True when the deployment itself could not serve the request and nothing ran (a dependency it relies on, its own
   * limits). Not that the caller did anything wrong, so a metered action refused with it is handed back to the caller's
   * allowance. The error says so itself; nothing lists codes.
   */
  public readonly stackSide: boolean;

  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number = 500,
    public readonly details?: Record<string, unknown>,
    options: { stackSide?: boolean } = {},
  ) {
    super(message);
    this.name = 'StackError';
    this.stackSide = options.stackSide === true;
  }
}
