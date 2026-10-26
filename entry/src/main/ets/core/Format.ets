/**
 * Presentation helpers. Numbers on this screen are read at a glance, so they
 * are formatted with fixed units and fixed decimals — never "1.0 MB" one tick
 * and "1 MB" the next.
 */

export function formatBytes(bytes: number): string {
  if (!isFinite(bytes) || bytes <= 0) {
    return '0 B';
  }
  const units: string[] = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value: number = bytes;
  let unit: number = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value = value / 1024;
    unit++;
  }
  if (unit === 0) {
    return Math.round(value).toString() + ' B';
  }
  return value.toFixed(value >= 100 ? 0 : 1) + ' ' + units[unit];
}

export function formatRate(bytesPerSecond: number): string {
  return formatBytes(bytesPerSecond) + '/s';
}

export function formatDuration(totalSeconds: number): string {
  if (!isFinite(totalSeconds) || totalSeconds < 0) {
    return '--';
  }
  const s: number = Math.floor(totalSeconds);
  if (s < 60) {
    return s.toString() + ' 秒';
  }
  const m: number = Math.floor(s / 60);
  if (m < 60) {
    return m.toString() + ' 分 ' + (s % 60).toString() + ' 秒';
  }
  const h: number = Math.floor(m / 60);
  if (h < 24) {
    return h.toString() + ' 时 ' + (m % 60).toString() + ' 分';
  }
  const d: number = Math.floor(h / 24);
  return d.toString() + ' 天 ' + (h % 24).toString() + ' 时';
}

/** Clock of a unix-seconds timestamp, e.g. 14:03:22. */
export function formatClock(unixSeconds: number): string {
  if (!isFinite(unixSeconds) || unixSeconds <= 0) {
    return '--:--:--';
  }
  const d: Date = new Date(unixSeconds * 1000);
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

/** Short date + clock, e.g. 10-25 14:03. */
export function formatDateTime(unixSeconds: number): string {
  if (!isFinite(unixSeconds) || unixSeconds <= 0) {
    return '从未';
  }
  const d: Date = new Date(unixSeconds * 1000);
  return pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' +
    pad2(d.getHours()) + ':' + pad2(d.getMinutes());
}

export function formatDelay(delayMs: number): string {
  if (delayMs <= 0) {
    return '--';
  }
  return delayMs.toString() + ' ms';
}

/** Fixed-width percentage-ish label for the traffic counters. */
export function formatCount(n: number): string {
  if (!isFinite(n) || n <= 0) {
    return '0';
  }
  if (n < 10000) {
    return Math.round(n).toString();
  }
  if (n < 1000000) {
    return (n / 1000).toFixed(1) + 'k';
  }
  return (n / 1000000).toFixed(1) + 'M';
}

function pad2(n: number): string {
  return n < 10 ? '0' + n.toString() : n.toString();
}
