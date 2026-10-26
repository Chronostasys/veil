import { socket } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';
import { HostReply, HostRequest, RpcRequest } from '../model/Types';

/**
 * LocalRpc — newline-delimited JSON over a Unix domain socket.
 *
 * One instance == one connection. The UI process and the VPN extension process
 * each own their own instance; the core is the server on
 * `<filesDir>/veil.sock`.
 *
 * Framing (see ets/README.md):
 *   client -> core : {"id":1,"method":"status","params":{}}\n
 *   core -> client : {"id":1,"ok":true,"result":{...}}\n
 *   core -> host   : {"host":true,"id":7,"method":"tun_up","params":{}}\n
 *   host -> core   : {"id":7,"ok":true,"result":{"fd":42}}\n
 *
 * The transport splits on '\n', so a single socket read may carry half a frame
 * or five frames; `buf` absorbs the partial one.
 */

export class RpcError extends Error {
  readonly code: number;

  constructor(message: string, code: number = 0) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
  }
}

/** Parsed frame. Every field is optional because we only know what arrived. */
interface InboundFrame {
  host?: boolean;
  role?: string;
  id?: number;
  ok?: boolean;
  result?: Object;
  error?: string;
  method?: string;
  params?: Object;
}

interface PendingCall {
  resolve: (value: Object) => void;
  // Rejections carry an RpcError; typed as Object because ArkTS has no
  // structural typing and the built-in `Error` is not nominal-compatible.
  reject: (reason: Object) => void;
  timer: number;
}

export class EmptyResult {
}

/**
 * A host handler performs the side effect and calls back with the reply. It is
 * invoked from the socket callback, so it must not block.
 */
export type HostHandler = (req: HostRequest, done: (ok: boolean, result: Object, error: string) => void) => void;

/** Fired when the peer goes away (used by the ability to stop the engine). */
export type CloseListener = (reason: string) => void;

export class LocalRpc {
  private sock: socket.LocalSocket | null = null;
  private buf: string = '';
  private nextId: number = 1;
  private pending: Map<number, PendingCall> = new Map<number, PendingCall>();
  private hostHandler: HostHandler | null = null;
  private closeListener: CloseListener | null = null;
  private sendChain: Promise<void> = Promise.resolve();
  private decoder: util.TextDecoder = util.TextDecoder.create('utf-8');
  private open: boolean = false;

  isOpen(): boolean {
    return this.open;
  }

  onHostRequest(handler: HostHandler): void {
    this.hostHandler = handler;
  }

  onClose(listener: CloseListener): void {
    this.closeListener = listener;
  }

  /** Connects once. Throws RpcError on failure; retry policy lives in the caller. */
  async connect(path: string, timeoutMs: number = 2000): Promise<void> {
    this.close();
    const s: socket.LocalSocket = socket.constructLocalSocketInstance();
    s.on('message', (info: socket.LocalSocketMessageInfo) => {
      this.onData(info);
    });
    s.on('close', () => {
      this.onClosed('本地套接字已关闭');
    });
    s.on('error', (err: BusinessError) => {
      this.onClosed('本地套接字错误: ' + err.message);
    });
    const opts: socket.LocalConnectOptions = {
      address: { address: path },
      timeout: timeoutMs
    };
    try {
      await s.connect(opts);
    } catch (err) {
      const be: BusinessError = err as BusinessError;
      throw new RpcError('无法连接核心套接字: ' + formatSocketError(be));
    }
    this.sock = s;
    this.open = true;
    this.buf = '';
    this.sendChain = Promise.resolve();
  }

  /** Announces this connection as the VPN extension host (first line). */
  async hello(): Promise<void> {
    await this.sendLine('{"role":"host"}\n');
  }

  async request(method: string, params: Object, timeoutMs: number = 8000): Promise<Object> {
    if (!this.open) {
      throw new RpcError('核心未连接');
    }
    const id: number = this.nextId;
    this.nextId = this.nextId + 1;
    const req: RpcRequest = { id: id, method: method, params: params };
    const payload: string = JSON.stringify(req) + '\n';

    const call: Promise<Object> = new Promise<Object>(
      (resolve: (value: Object) => void, reject: (reason: Object) => void): void => {
        const timer: number = setTimeout(() => {
          this.pending.delete(id);
          reject(new RpcError('请求超时: ' + method));
        }, timeoutMs);
        const entry: PendingCall = { resolve: resolve, reject: reject, timer: timer };
        this.pending.set(id, entry);
      });

    try {
      await this.sendLine(payload);
    } catch (err) {
      const entry: PendingCall | undefined = this.pending.get(id);
      if (entry !== undefined) {
        this.pending.delete(id);
        clearTimeout(entry.timer);
        entry.reject(err as Object);
      }
    }
    return call;
  }

  sendHostReply(id: number, ok: boolean, result: Object, error: string): void {
    const rep: HostReply = { id: id, ok: ok };
    if (ok) {
      rep.result = result;
    } else {
      rep.error = error;
    }
    this.sendLine(JSON.stringify(rep) + '\n').catch((_e: Error): void => {
      // The core is gone; nothing left to tell it.
    });
  }

  close(): void {
    const s: socket.LocalSocket | null = this.sock;
    this.sock = null;
    this.open = false;
    if (s !== null) {
      s.off('message');
      s.off('close');
      s.off('error');
      s.close().catch((_e: Error): void => {
      });
    }
    this.buf = '';
    this.rejectAll('连接已关闭');
  }

  // -- internals ------------------------------------------------------------

  private rejectAll(reason: string): void {
    const ids: number[] = Array.from(this.pending.keys());
    for (let i = 0; i < ids.length; i++) {
      const entry: PendingCall | undefined = this.pending.get(ids[i]);
      if (entry !== undefined) {
        clearTimeout(entry.timer);
        entry.reject(new RpcError(reason));
      }
    }
    this.pending.clear();
  }

  private onClosed(reason: string): void {
    if (!this.open) {
      return;
    }
    this.open = false;
    this.sock = null;
    this.rejectAll(reason);
    const l: CloseListener | null = this.closeListener;
    if (l !== null) {
      l(reason);
    }
  }

  private onData(info: socket.LocalSocketMessageInfo): void {
    let text: string = '';
    try {
      text = this.decoder.decodeToString(new Uint8Array(info.message));
    } catch (err) {
      return;
    }
    this.buf = this.buf + text;
    let idx: number = this.buf.indexOf('\n');
    while (idx >= 0) {
      const line: string = this.buf.substring(0, idx);
      this.buf = this.buf.substring(idx + 1);
      const trimmed: string = line.trim();
      if (trimmed.length > 0) {
        this.dispatch(trimmed);
      }
      idx = this.buf.indexOf('\n');
    }
  }

  private dispatch(line: string): void {
    let frame: InboundFrame;
    try {
      frame = JSON.parse(line) as InboundFrame;
    } catch (err) {
      return;
    }
    if (frame.host === true) {
      this.dispatchHost(frame);
      return;
    }
    const id: number | undefined = frame.id;
    if (id === undefined) {
      return;
    }
    const entry: PendingCall | undefined = this.pending.get(id);
    if (entry === undefined) {
      // Stale reply (timed out already) — drop it silently.
      return;
    }
    this.pending.delete(id);
    clearTimeout(entry.timer);
    if (frame.ok === true) {
      entry.resolve(frame.result === undefined ? new EmptyResult() : frame.result);
    } else {
      entry.reject(new RpcError(frame.error === undefined ? '核心返回未知错误' : frame.error));
    }  }

  private dispatchHost(frame: InboundFrame): void {
    const handler: HostHandler | null = this.hostHandler;
    if (handler === null) {
      return;
    }
    const req: HostRequest = {
      host: true,
      id: frame.id === undefined ? 0 : frame.id,
      method: frame.method === undefined ? '' : frame.method,
      params: frame.params
    };
    handler(req, (ok: boolean, result: Object, error: string): void => {
      this.sendHostReply(req.id, ok, result, error);
    });
  }

  private sendLine(line: string): Promise<void> {
    const prev: Promise<void> = this.sendChain;
    const cur: Promise<void> = prev.then((): Promise<void> => this.rawSend(line));
    this.sendChain = cur.then((): void => {
    }).catch((_e: Error): void => {
    });
    return cur;
  }

  private async rawSend(line: string): Promise<void> {
    const s: socket.LocalSocket | null = this.sock;
    if (s === null || !this.open) {
      throw new RpcError('核心未连接');
    }
    const opt: socket.LocalSendOptions = { data: line };
    await s.send(opt);
  }
}

function formatSocketError(err: BusinessError): string {
  if (err === undefined || err === null) {
    return '未知错误';
  }
  return err.message + ' (' + err.code.toString() + ')';
}
