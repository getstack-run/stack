/**
 * Where activation milestones go. STACK's hosted deployment sends them to its
 * product analytics; an install sends nothing to anyone, which is
 * `NO_ANALYTICS`.
 */
export interface AnalyticsSink {
  /** Fire an event exactly once per operator. Never throws into a request path. */
  fireOnce(operatorId: string, event: string, properties?: Record<string, unknown>): Promise<void>;
  /** Fire an event every time. */
  capture(operatorId: string, event: string, properties?: Record<string, unknown>): void;
  shutdown(): Promise<void>;
}

export const NO_ANALYTICS: AnalyticsSink = {
  async fireOnce() {},
  capture() {},
  async shutdown() {},
};
