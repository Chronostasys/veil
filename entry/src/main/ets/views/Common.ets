import { promptAction } from '@kit.ArkUI';
import { CoreState } from '../core/CoreClient';

/** Single entry point for user-visible errors: always the real message. */
export function toast(message: string): void {
  promptAction.showToast({ message: message, duration: 2600 });
}

export function errorText(err: Object): string {
  const e: Error = err as Error;
  if (e === undefined || e === null) {
    return '未知错误';
  }
  const msg: string = e.message;
  return msg === undefined || msg.length === 0 ? '未知错误' : msg;
}

export function coreStateLabel(state: CoreState): string {
  if (state === CoreState.Ready) {
    return '核心已连接';
  }
  if (state === CoreState.Connecting) {
    return '正在连接核心';
  }
  if (state === CoreState.Unavailable) {
    return '核心不可用';
  }
  return '核心未启动';
}
