/**
 * Cooperative decode control: lets the UI pause, resume or cancel a long
 * running PCAP decode. The parser calls `gate()` periodically; the gate yields
 * to the event loop (keeping the UI responsive), blocks while paused and
 * throws `DecodeCancelledError` once cancelled.
 */

export class DecodeCancelledError extends Error {
  constructor() {
    super('Decode cancelled by user');
    this.name = 'DecodeCancelledError';
  }
}

export class DecodeController {
  private paused = false;
  private cancelled = false;
  private resumeWaiters: Array<() => void> = [];

  pause() {
    this.paused = true;
  }

  resume() {
    this.paused = false;
    const waiters = this.resumeWaiters;
    this.resumeWaiters = [];
    waiters.forEach((w) => w());
  }

  cancel() {
    this.cancelled = true;
    this.resume();
  }

  get isPaused() {
    return this.paused;
  }

  get isCancelled() {
    return this.cancelled;
  }

  /** Yield control; blocks while paused, throws when cancelled. */
  async gate(): Promise<void> {
    if (this.cancelled) throw new DecodeCancelledError();
    await new Promise<void>((r) => setTimeout(r, 0));
    while (this.paused && !this.cancelled) {
      await new Promise<void>((r) => this.resumeWaiters.push(r));
    }
    if (this.cancelled) throw new DecodeCancelledError();
  }
}

export const isDecodeCancelled = (error: unknown) =>
  error instanceof DecodeCancelledError ||
  (error instanceof Error && error.name === 'DecodeCancelledError');
