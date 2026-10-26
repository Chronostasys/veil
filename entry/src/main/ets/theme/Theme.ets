/**
 * Canvas-drawn surfaces (sparkline, power ring, tab glyphs) need concrete
 * colour strings, and Canvas cannot resolve `$r()` resources. This palette
 * mirrors resources/base/element/color.json and resources/dark/element/color.json
 * exactly — if you change a colour there, change it here too.
 */

export interface ThemeColors {
  bg: string;
  surface: string;
  surfaceAlt: string;
  hairline: string;
  text: string;
  textDim: string;
  textFaint: string;
  teal: string;
  indigo: string;
  ok: string;
  warn: string;
  err: string;
}

export function darkTheme(): ThemeColors {
  const c: ThemeColors = {
    bg: '#0B0D10',
    surface: '#12151B',
    surfaceAlt: '#1A1F27',
    hairline: '#232A35',
    text: '#E9EEF6',
    textDim: '#8B94A5',
    textFaint: '#59616F',
    teal: '#5EEAD4',
    indigo: '#6366F1',
    ok: '#34D399',
    warn: '#FBBF24',
    err: '#F87171'
  };
  return c;
}

export function lightTheme(): ThemeColors {
  const c: ThemeColors = {
    bg: '#F4F6F9',
    surface: '#FFFFFF',
    surfaceAlt: '#EDF0F5',
    hairline: '#E2E6EE',
    text: '#0E1218',
    textDim: '#5B6474',
    textFaint: '#96A0B0',
    teal: '#0E9F8E',
    indigo: '#5B5BE6',
    ok: '#059669',
    warn: '#D97706',
    err: '#DC2626'
  };
  return c;
}

export function themeOf(dark: boolean): ThemeColors {
  return dark ? darkTheme() : lightTheme();
}

/** Phase → accent colour. The UI never shows "connected" without a phase. */
export function phaseColor(dark: boolean, phase: string): string {
  const c: ThemeColors = themeOf(dark);
  if (phase === 'running') {
    return c.teal;
  }
  if (phase === 'degraded') {
    return c.warn;
  }
  if (phase === 'failed') {
    return c.err;
  }
  if (phase === 'starting' || phase === 'stopping') {
    return c.indigo;
  }
  return c.textFaint;
}

export function phaseLabel(phase: string): string {
  if (phase === 'running') {
    return '已连接';
  }
  if (phase === 'starting') {
    return '正在启动';
  }
  if (phase === 'stopping') {
    return '正在停止';
  }
  if (phase === 'degraded') {
    return '部分可用';
  }
  if (phase === 'failed') {
    return '启动失败';
  }
  return '未连接';
}

/** Delay → colour bucket, shared by the node list and the status card. */
export function delayColor(dark: boolean, delayMs: number): string {
  const c: ThemeColors = themeOf(dark);
  if (delayMs <= 0) {
    return c.textFaint;
  }
  if (delayMs < 150) {
    return c.teal;
  }
  if (delayMs < 400) {
    return c.ok;
  }
  if (delayMs < 800) {
    return c.warn;
  }
  return c.err;
}
