import { CoreClient } from '../core/CoreClient';
import { K_MODE, K_STATUS, Store } from '../core/Store';
import { formatBytes, formatCount, formatDuration, formatRate } from '../core/Format';
import { emptyStatus, normalizeStatus, Phase, Status } from '../model/Types';
import { phaseColor, phaseLabel, themeOf, ThemeColors } from '../theme/Theme';
import { Chip, EmptyBlock, Hairline, SectionTitle, Tag } from './Ui';
import { Glyph } from './Glyph';
import { errorText, toast } from './Common';

const SAMPLE_COUNT: number = 60;
// Adaptive polling: snappy while the tunnel is live, calm and battery-friendly
// when it is idle. Background screens stop polling entirely (aboutToDisappear).
const POLL_ACTIVE_MS: number = 800;
const POLL_IDLE_MS: number = 3000;

/**
 * 连接 — the only screen allowed to imply "connected", and it derives that word
 * from `status.phase` (measured by the core's watchdog), never from a local flag.
 */
@Component
export struct HomeView {
  @StorageProp('veilDark') dark: boolean = true;
  @Link @Watch('onCoreReady') coreReady: boolean;
  @StorageProp(K_STATUS) status: Status = emptyStatus();
  @State samples: number[] = [];
  @State busy: boolean = false;
  @State canvasReady: boolean = false;
  @State pressScale: number = 1;

  private timer: number = -1;
  private inFlight: boolean = false;
  private settings: RenderingContextSettings = new RenderingContextSettings(true);
  private ctx: CanvasRenderingContext2D = new CanvasRenderingContext2D(this.settings);

  aboutToAppear(): void {
    if (this.coreReady) {
      this.startPolling();
    }
  }

  aboutToDisappear(): void {
    this.stopPolling();
  }

  onCoreReady(): void {
    if (this.coreReady) {
      this.startPolling();
    } else {
      this.stopPolling();
    }
  }

  private startPolling(): void {
    this.stopPolling();
    this.poll();
  }

  private schedule(): void {
    this.stopPolling();
    const active: boolean = Phase.isActive(this.status.phase) || this.busy;
    this.timer = setTimeout(() => {
      this.poll();
    }, active ? POLL_ACTIVE_MS : POLL_IDLE_MS);
  }

  private stopPolling(): void {
    if (this.timer >= 0) {
      clearTimeout(this.timer);
      this.timer = -1;
    }
  }

  private async poll(): Promise<void> {
    if (!this.coreReady) {
      this.stopPolling();
      return;
    }
    if (this.inFlight) {
      this.schedule();
      return;
    }
    this.inFlight = true;
    const prevPhase: string = this.status.phase;
    try {
      const s: Status | null = await Store.get().refresh();
      if (s !== null) {
        this.pushSample(s.traffic.down_rate);
        this.notifyPhase(prevPhase);
      }
    } catch (err) {
      // Transient RPC failures are not state; the core-availability banner in
      // Index handles real disconnects.
    }
    this.inFlight = false;
    this.schedule();
  }

  /** Speak only when the phase really changes; silent on the first sample. */
  private notifyPhase(prev: string): void {
    const now: string = this.status.phase;
    if (prev === now || prev.length === 0) {
      return;
    }
    const reason: string = this.status.reason === undefined ? '' : this.status.reason;
    if (now === Phase.RUNNING) {
      toast('已连接');
    } else if (now === Phase.DEGRADED) {
      toast('连接降级: ' + (reason.length > 0 ? reason : '数据面异常'));
    } else if (now === Phase.FAILED) {
      toast('连接失败: ' + (reason.length > 0 ? reason : '核心报错'));
    } else if (prev === Phase.RUNNING || prev === Phase.DEGRADED) {
      toast('已断开');
    }
  }

  private pushSample(value: number): void {
    const next: number[] = this.samples.slice();
    next.push(value < 0 ? 0 : value);
    while (next.length > SAMPLE_COUNT) {
      next.shift();
    }
    this.samples = next;
    this.drawSpark();
  }

  private async togglePower(): Promise<void> {
    if (this.busy) {
      return;
    }
    if (!this.coreReady) {
      toast('核心不可用，无法切换连接');
      return;
    }
    const active: boolean = Phase.isActive(this.status.phase);
    this.busy = true;
    try {
      if (active) {
        await Store.get().stop();
      } else {
        await Store.get().start();
      }
      await this.poll();
      toast(active ? '已请求停止' : '已请求启动');
    } catch (err) {
      toast(errorText(err));
    }
    this.busy = false;
  }

  private async switchMode(mode: string): Promise<void> {
    if (this.status.mode === mode) {
      return;
    }
    try {
      await Store.get().setMode(mode);
    } catch (err) {
      toast(errorText(err));
    }
  }

  private currentNodes(): string {
    const groups = this.status.groups;
    for (let i = 0; i < groups.length; i++) {
      if (groups[i].now.length > 0) {
        return groups[i].now;
      }
    }
    return '';
  }

  private reasonText(): string {
    const reason: string = this.status.reason === undefined ? '' : this.status.reason;
    if (reason.length > 0) {
      return reason;
    }
    const tunErr: string = this.status.tun.err === undefined ? '' : this.status.tun.err;
    if (tunErr.length > 0) {
      return 'tun 异常: ' + tunErr;
    }
    return '';
  }

  private drawSpark(): void {
    if (!this.canvasReady) {
      return;
    }
    const ctx: CanvasRenderingContext2D = this.ctx;
    const w: number = ctx.width;
    const h: number = ctx.height;
    if (w <= 0 || h <= 0) {
      return;
    }
    const c: ThemeColors = themeOf(this.dark);
    ctx.clearRect(0, 0, w, h);

    // Baseline: a hairline so an idle graph still looks intentional.
    ctx.strokeStyle = c.hairline;
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    ctx.moveTo(0, h - 0.5);
    ctx.lineTo(w, h - 0.5);
    ctx.stroke();

    const n: number = this.samples.length;
    if (n < 2) {
      return;
    }
    let max: number = 1;
    for (let i = 0; i < n; i++) {
      if (this.samples[i] > max) {
        max = this.samples[i];
      }
    }

    const top: number = 4;
    const usable: number = h - top - 2;
    const xOf = (i: number): number => (i / (n - 1)) * w;
    const yOf = (v: number): number => h - 2 - (v / max) * usable;

    // Area fill with the aurora tint at the top.
    const grad: CanvasGradient = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, c.teal + '4D');
    grad.addColorStop(1, c.indigo + '00');
    ctx.beginPath();
    ctx.moveTo(xOf(0), h);
    for (let i = 0; i < n; i++) {
      ctx.lineTo(xOf(i), yOf(this.samples[i]));
    }
    ctx.lineTo(xOf(n - 1), h);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Stroke on top.
    ctx.beginPath();
    ctx.moveTo(xOf(0), yOf(this.samples[0]));
    for (let i = 1; i < n; i++) {
      ctx.lineTo(xOf(i), yOf(this.samples[i]));
    }
    ctx.strokeStyle = c.teal;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();
  }

  @Builder
  powerButton() {
    Stack() {
      Column()
        .width(78)
        .height(78)
        .borderRadius(39)
        .linearGradient({
          angle: 145,
          colors: [[$r('app.color.veil_teal'), 0.0], [$r('app.color.veil_indigo'), 1.0]]
        })
        .opacity(Phase.isActive(this.status.phase) ? 1 : 0.18)

      if (this.busy) {
        LoadingProgress()
          .width(30)
          .height(30)
          .color(Color.White)
      } else {
        Glyph({ kind: 'power', tint: '#FFFFFF', dim: 34, weight: 2 })
      }
    }
    .width(78)
    .height(78)
    .borderRadius(39)
    .scale({ x: this.pressScale, y: this.pressScale })
    .shadow({
      radius: 22,
      color: Phase.isActive(this.status.phase) ? '#5EEAD455' : '#00000000',
      offsetX: 0,
      offsetY: 6
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        animateTo({ duration: 90, curve: Curve.Sharp }, () => {
          this.pressScale = 0.93;
        });
      } else if (event.type === TouchType.Up || event.type === TouchType.Cancel) {
        animateTo({ duration: 180, curve: Curve.Friction }, () => {
          this.pressScale = 1;
        });
      }
    })
    .onClick(() => {
      this.togglePower();
    })
  }

  @Builder
  rateBlock(label: string, arrow: string, value: string, tone: ResourceColor) {
    Column({ space: 2 }) {
      Row({ space: 4 }) {
        Text(arrow)
          .fontSize(11)
          .fontColor(tone)
        Text(label)
          .fontSize(11)
          .fontColor($r('app.color.veil_text_faint'))
      }

      Text(value)
        .fontSize(15)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.veil_text'))
        .fontFeature('"tnum" 1')
    }
    .alignItems(HorizontalAlign.Start)
  }

  build() {
    Scroll() {
      Column({ space: 14 }) {
        // ---- status card ------------------------------------------------
        Column({ space: 16 }) {
          Row() {
            Column({ space: 6 }) {
              Text(this.currentNodes().length > 0 ? this.currentNodes() : '未选择节点')
                .fontSize(21)
                .fontWeight(FontWeight.Medium)
                .fontColor($r('app.color.veil_text'))
                .maxLines(1)
                .textOverflow({ overflow: TextOverflow.Ellipsis })

              Row({ space: 8 }) {
                Row({ space: 5 }) {
                  Circle()
                    .width(6)
                    .height(6)
                    .fill(phaseColor(this.dark, this.status.phase))
                  Text(phaseLabel(this.status.phase))
                    .fontSize(12)
                    .fontColor(phaseColor(this.dark, this.status.phase))
                }

                Text('·')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_text_faint'))

                Text(Phase.isActive(this.status.phase) ? formatDuration(this.status.uptime_sec) : '未运行')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_text_dim'))
                  .fontFeature('"tnum" 1')
              }
            }
            .alignItems(HorizontalAlign.Start)
            .layoutWeight(1)

            this.powerButton()
          }
          .width('100%')
          .alignItems(VerticalAlign.Center)

          if (this.reasonText().length > 0) {
            Row({ space: 6 }) {
              Column()
                .width(2)
                .height(28)
                .borderRadius(1)
                .backgroundColor(phaseColor(this.dark, this.status.phase))
              Text(this.reasonText())
                .fontSize(12)
                .fontColor($r('app.color.veil_text_dim'))
                .layoutWeight(1)
                .maxLines(3)
            }
            .width('100%')
            .alignItems(VerticalAlign.Center)
          }

          // ---- live rate sparkline -------------------------------------
          Column({ space: 6 }) {
            Canvas(this.ctx)
              .width('100%')
              .height(54)
              .onReady(() => {
                this.canvasReady = true;
                this.drawSpark();
              })

            Row() {
              this.rateBlock('下载', '↓', formatRate(this.status.traffic.down_rate),
                $r('app.color.veil_teal'))
              Blank()
              this.rateBlock('上传', '↑', formatRate(this.status.traffic.up_rate),
                $r('app.color.veil_indigo'))
              Blank()
              this.rateBlock('连接', '', formatCount(this.status.traffic.active),
                $r('app.color.veil_text_dim'))
            }
            .width('100%')
          }

          Hairline()

          Row() {
            Text('累计 ↓ ' + formatBytes(this.status.traffic.down))
              .fontSize(11)
              .fontColor($r('app.color.veil_text_faint'))
              .fontFeature('"tnum" 1')
            Blank()
            Text('累计 ↑ ' + formatBytes(this.status.traffic.up))
              .fontSize(11)
              .fontColor($r('app.color.veil_text_faint'))
              .fontFeature('"tnum" 1')
          }
          .width('100%')
        }
        .width('100%')
        .padding(20)
        .borderRadius(24)
        .backgroundColor($r('app.color.veil_surface'))
        .border({ width: 0.5, color: $r('app.color.veil_hairline') })

        // ---- routing mode ------------------------------------------------
        Column({ space: 10 }) {
          Row() {
            Text('分流模式')
              .fontSize(13)
              .fontColor($r('app.color.veil_text_dim'))
            Blank()
            Text('规则 / 全局 / 直连')
              .fontSize(11)
              .fontColor($r('app.color.veil_text_faint'))
          }
          .width('100%')

          Row({ space: 8 }) {
            Chip({
              label: '规则',
              active: this.status.mode === 'rule',
              tone: this.dark ? '#5EEAD4' : '#0E9F8E',
              onTap: () => {
                this.switchMode('rule');
              }
            })
            Chip({
              label: '全局',
              active: this.status.mode === 'global',
              tone: this.dark ? '#5EEAD4' : '#0E9F8E',
              onTap: () => {
                this.switchMode('global');
              }
            })
            Chip({
              label: '直连',
              active: this.status.mode === 'direct',
              tone: this.dark ? '#5EEAD4' : '#0E9F8E',
              onTap: () => {
                this.switchMode('direct');
              }
            })
          }
          .width('100%')
        }
        .width('100%')
        .padding(16)
        .borderRadius(20)
        .backgroundColor($r('app.color.veil_surface'))
        .border({ width: 0.5, color: $r('app.color.veil_hairline') })

        // ---- process health: the "does not lie" section ------------------
        Column({ space: 2 }) {
          SectionTitle({ title: '运行状态' })

          Row() {
            Text('心跳')
              .fontSize(13)
              .fontColor($r('app.color.veil_text_dim'))
            Blank()
            Text(this.status.health.heartbeat_ago_ms < 0 ?
              '—' : this.status.health.heartbeat_ago_ms.toString() + ' ms 前')
              .fontSize(13)
              .fontFeature('"tnum" 1')
              .fontColor(this.status.health.heartbeat_ago_ms > 3000 ?
                $r('app.color.veil_err') : $r('app.color.veil_text_dim'))
          }
          .width('100%')
          .padding({ top: 8, bottom: 8 })

          Hairline()

          Row() {
            Text('重启次数')
              .fontSize(13)
              .fontColor($r('app.color.veil_text_dim'))
            Blank()
            Text(this.status.health.restarts.toString())
              .fontSize(13)
              .fontFeature('"tnum" 1')
              .fontColor(this.status.health.restarts > 0 ?
                $r('app.color.veil_warn') : $r('app.color.veil_text_dim'))
          }
          .width('100%')
          .padding({ top: 8, bottom: 8 })

          Hairline()

          Row() {
            Text('协程 / 句柄')
              .fontSize(13)
              .fontColor($r('app.color.veil_text_dim'))
            Blank()
            Text(this.status.health.goroutines.toString() + ' / ' +
              this.status.health.open_fds.toString())
              .fontSize(13)
              .fontFeature('"tnum" 1')
              .fontColor($r('app.color.veil_text_dim'))
          }
          .width('100%')
          .padding({ top: 8, bottom: 8 })

          Hairline()

          Row() {
            Text('Tun / DNS')
              .fontSize(13)
              .fontColor($r('app.color.veil_text_dim'))
            Blank()
            Tag({
              label: this.status.tun.up ? 'tun 已就绪' : 'tun 未就绪',
              tone: this.status.tun.up ? (this.dark ? '#34D399' : '#059669') :
                (this.dark ? '#59616F' : '#96A0B0')
            })
            Blank().width(6)
            Tag({
              label: this.status.dns.enabled ? 'DNS 已启用' : 'DNS 关闭',
              tone: this.status.dns.enabled ? (this.dark ? '#5EEAD4' : '#0E9F8E') :
                (this.dark ? '#59616F' : '#96A0B0')
            })
          }
          .width('100%')
          .padding({ top: 8, bottom: 8 })
        }
        .width('100%')
        .padding(16)
        .borderRadius(20)
        .backgroundColor($r('app.color.veil_surface'))
        .border({ width: 0.5, color: $r('app.color.veil_hairline') })

        if (!this.coreReady) {
          EmptyBlock({
            title: '核心未连接',
            subtitle: '统计与开关都来自核心的实时上报，未连接时不会显示任何“已连接”状态。'
          })
        }

        Column().height(12)
      }
      .width('100%')
      .padding({ left: 18, right: 18, top: 8 })
    }
    .scrollBar(BarState.Off)
    .edgeEffect(EdgeEffect.Spring)
    .width('100%')
    .height('100%')
    .onVisibleAreaChange([0.0, 1.0], (isVisible: boolean, ratio: number) => {
      // Poll only while this tab is on screen: a background tab must not cost
      // a status RPC every second.
      if (isVisible && ratio > 0) {
        if (this.coreReady) {
          this.startPolling();
        }
      } else {
        this.stopPolling();
      }
    })
  }
}
