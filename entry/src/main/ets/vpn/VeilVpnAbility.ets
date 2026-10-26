import { VpnExtensionAbility, vpnExtension } from '@kit.NetworkKit';
import { Want } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import veil from 'libveil.so';
import { LocalRpc, RpcError } from '../core/LocalRpc';
import { HostRequest, ProtectParams, TunUpParams, TunUpResult } from '../model/Types';

const TAG = 'VeilVpn';

/** JSON the shim returns; only `ok` and `error` matter here. */
interface ShimReply {
  ok?: boolean;
  error?: string;
}

const CONNECT_TRIES = 20;
const CONNECT_DELAY_MS = 250;

/**
 * The VPN extension is the RPC *host*.
 *
 * It is the only process that loads libveilcore.so (through the NAPI shim), it
 * owns the tun fd returned by VpnConnection.create(), and it answers the core's
 * host requests:
 *
 *   protect  {fd}  -> vpnConnection.protect(fd)
 *   tun_up   {mtu} -> createVpnConnection + create() -> {fd}
 *   tun_down {}    -> destroy()
 *
 * The UI process talks to the same core over the same socket; it just never
 * sees host requests.
 */
// Process-wide VPN state. The extension can be instantiated more than once in
// the same process (e.g. the desktop card starts it while the app also does),
// and only one instance owns the tun. Sharing the VpnConnection across
// instances keeps protect() working no matter which instance answers.
let sharedConn: vpnExtension.VpnConnection | null = null;
let sharedTunFd: number = -1;

export default class VeilVpnAbility extends VpnExtensionAbility {
  private rpc: LocalRpc = new LocalRpc();
  private shuttingDown: boolean = false;

  onCreate(_want: Want): void {
    const filesDir: string = this.context.filesDir;
    const configPath: string = filesDir + '/config.json';
    const socketPath: string = filesDir + '/veil.sock';
    hilog.info(0x0000, TAG, 'onCreate, filesDir=%{public}s', filesDir);

    this.rpc.onHostRequest((req: HostRequest, done: (ok: boolean, result: Object, error: string) => void) => {
      this.handleHostRequest(req, done);
    });
    this.rpc.onClose((reason: string) => {
      hilog.warn(0x0000, TAG, 'socket closed: %{public}s', reason);
      if (!this.shuttingDown) {
        this.scheduleReconnect(socketPath);
      }
    });

    const reply: string = veil.start(configPath, socketPath);
    const shim: ShimReply = JSON.parse(reply) as ShimReply;
    if (shim.ok !== true) {
      hilog.error(0x0000, TAG, 'core start failed: %{public}s',
        shim.error === undefined ? 'unknown' : shim.error);
    }
    this.connectHost(socketPath);
  }

  onDestroy(): void {
    hilog.info(0x0000, TAG, 'onDestroy');
    this.shuttingDown = true;
    this.rpc.close();
    if (sharedConn !== null) {
      sharedConn.destroy().catch((_e: Error): void => {
      });
      sharedConn = null;
    }
    sharedTunFd = -1;
    // Do NOT call veil.shutdown() here. The extension can be recreated while a
    // previous instance is still tearing down (card taps used to trigger that);
    // shutting the core down from onDestroy made the UI report "核心不可用"
    // even though the process and the tunnel were fine. The core dies with the
    // process, and VeilStart() is idempotent if an instance is reused.
  }

  // -- socket side ----------------------------------------------------------

  private async connectHost(socketPath: string): Promise<void> {
    for (let attempt = 0; attempt < CONNECT_TRIES; attempt++) {
      if (this.shuttingDown) {
        return;
      }
      try {
        await this.rpc.connect(socketPath, 1500);
        await this.rpc.hello();
        hilog.info(0x0000, TAG, 'host connected to core (attempt %{public}d)', attempt + 1);
        return;
      } catch (err) {
        const re: RpcError = err as RpcError;
        if (attempt === CONNECT_TRIES - 1) {
          hilog.error(0x0000, TAG, 'host connect gave up: %{public}s', re.message);
        }
      }
      await sleep(CONNECT_DELAY_MS);
    }
  }

  private scheduleReconnect(socketPath: string): void {
    setTimeout(() => {
      if (!this.shuttingDown) {
        this.connectHost(socketPath);
      }
    }, 1000);
  }

  // -- host requests --------------------------------------------------------

  private handleHostRequest(req: HostRequest,
    done: (ok: boolean, result: Object, error: string) => void): void {
    switch (req.method) {
      case 'protect':
        this.doProtect(req, done);
        break;
      case 'tun_up':
        this.doTunUp(req, done);
        break;
      case 'tun_down':
        this.doTunDown(done);
        break;
      default:
        done(false, new EmptyObject(), '未知的 host 请求: ' + req.method);
        break;
    }
  }

  private async doProtect(req: HostRequest,
    done: (ok: boolean, result: Object, error: string) => void): Promise<void> {
    const params: ProtectParams = (req.params === undefined ? new EmptyObject() : req.params) as ProtectParams;
    const fd: number = params.fd === undefined ? -1 : params.fd;
    if (sharedConn === null) {
      // A fresh instance (card-started) may answer before any instance created
      // the connection. protect() only needs the VpnConnection object, so create
      // it here instead of failing every dial.
      try {
        sharedConn = vpnExtension.createVpnConnection(this.context);
        hilog.info(0x0000, TAG, 'lazily created VpnConnection for protect');
      } catch (err) {
        const be: BusinessError = err as BusinessError;
        done(false, new EmptyObject(), '尚未建立 tun 连接，无法 protect fd: ' + be.message);
        return;
      }
    }
    if (fd < 0) {
      done(false, new EmptyObject(), 'protect 需要合法的 fd');
      return;
    }
    try {
      await sharedConn.protect(fd);
      done(true, new EmptyObject(), '');
    } catch (err) {
      const be: BusinessError = err as BusinessError;
      done(false, new EmptyObject(), 'protect 失败: ' + be.message);
    }
  }

  private async doTunUp(req: HostRequest,
    done: (ok: boolean, result: Object, error: string) => void): Promise<void> {
    if (sharedTunFd >= 0 && sharedConn !== null) {
      // Idempotent: the core may ask again after a restart.
      const existing: TunUpResult = { fd: sharedTunFd };
      done(true, existing, '');
      return;
    }
    const params: TunUpParams = (req.params === undefined ? new EmptyObject() : req.params) as TunUpParams;
    const mtu: number = params.mtu === undefined || params.mtu <= 0 ? 1400 : params.mtu;
    const ipv4: string = params.ipv4 === undefined || params.ipv4.length === 0 ? '172.19.0.1' : params.ipv4;
    const dns: string = params.dns === undefined || params.dns.length === 0 ? '172.19.0.2' : params.dns;

    try {
      // Reuse the connection protect() may have lazily created: two VpnConnection
      // objects fight over the single VPN slot and create() then returns an
      // unusable fd (0), which starts an engine on stdin and kills the host.
      if (sharedConn === null) {
        sharedConn = vpnExtension.createVpnConnection(this.context);
      }
      const conn: vpnExtension.VpnConnection = sharedConn;
      const config: vpnExtension.VpnConfig = buildVpnConfig(mtu, ipv4, dns);
      const fd: number = await conn.create(config);
      if (fd < 3) {
        throw new Error('create() returned unusable fd ' + fd.toString());
      }
      sharedTunFd = fd;
      hilog.info(0x0000, TAG, 'tun up, fd=%{public}d mtu=%{public}d', fd, mtu);
      const result: TunUpResult = { fd: fd };
      done(true, result, '');
    } catch (err) {
      const be: BusinessError = err as BusinessError;
      // Release the half-created connection: leaving it alive makes the next
      // create() fail ("vpn already exists") and every protect() afterwards
      // targets a connection the system no longer accepts.
      const stale: vpnExtension.VpnConnection | null = sharedConn;
      sharedConn = null;
      sharedTunFd = -1;
      if (stale !== null) {
        stale.destroy().catch((_e: Error): void => {
        });
      }
      hilog.error(0x0000, TAG, 'tun up failed: %{public}s (%{public}d)', be.message, be.code);
      done(false, new EmptyObject(), '建立 tun 失败: ' + be.message + ' (' + be.code.toString() + ')');
    }
  }

  private async doTunDown(done: (ok: boolean, result: Object, error: string) => void): Promise<void> {
    const conn: vpnExtension.VpnConnection | null = sharedConn;
    sharedConn = null;
    sharedTunFd = -1;
    if (conn === null) {
      done(true, new EmptyObject(), '');
      return;
    }
    try {
      await conn.destroy();
      done(true, new EmptyObject(), '');
    } catch (err) {
      const be: BusinessError = err as BusinessError;
      done(false, new EmptyObject(), '销毁 tun 失败: ' + be.message);
    }
  }
}

/** Placeholder result object; JSON.stringify turns it into {}. */
class EmptyObject {
}

function buildVpnConfig(mtu: number, ipv4: string, dns: string): vpnExtension.VpnConfig {
  const address: vpnExtension.LinkAddress = {
    address: { address: ipv4, family: 1 },
    prefixLength: 30
  };
  const route4: vpnExtension.RouteInfo = {
    interface: 'vpn-tun',
    destination: { address: { address: '0.0.0.0', family: 1 }, prefixLength: 0 },
    gateway: { address: '0.0.0.0', family: 1 },
    hasGateway: false,
    isDefaultRoute: true
  };
  const route6: vpnExtension.RouteInfo = {
    interface: 'vpn-tun',
    destination: { address: { address: '::', family: 2 }, prefixLength: 0 },
    gateway: { address: '::', family: 2 },
    hasGateway: false,
    isDefaultRoute: true
  };
  const config: vpnExtension.VpnConfig = {
    addresses: [address],
    routes: [route4],
    dnsAddresses: [dns],
    mtu: mtu,
    isIPv6Accepted: false
  };
  return config;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve: () => void): void => {
    setTimeout(() => {
      resolve();
    }, ms);
  });
}
