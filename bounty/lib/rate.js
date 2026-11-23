// bounty/lib/rate.js — token bucket rate limiter + exponential backoff.
export class TokenBucket {
  constructor(ratePerSec = 10, burst = 10) {
    this.ratePerSec = ratePerSec;
    this.capacity = burst;
    this.tokens = burst;
    this.lastRefill = Date.now();
  }

  _refill() {
    const now = Date.now();
    const elapsedSec = (now - this.lastRefill) / 1000;
    if (elapsedSec > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsedSec * this.ratePerSec);
      this.lastRefill = now;
    }
  }

  tryAcquire() {
    this._refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  async acquire() {
    while (!this.tryAcquire()) {
      const deficit = 1 - this.tokens;
      const waitMs = Math.max(1, Math.ceil((deficit / this.ratePerSec) * 1000));
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
}

export function backoffDelay(attempt) {
  const n = Math.max(0, Number(attempt) || 0);
  return Math.min(1000 * 2 ** n, 30000);
}

export default { TokenBucket, backoffDelay };
