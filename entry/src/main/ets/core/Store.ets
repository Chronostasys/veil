import { formBindingData, formProvider } from '@kit.FormKit';
import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CoreClient } from './CoreClient';
import { formatBytes, formatRate } from './Format';
import { Phase, Status } from '../model/Types';

const TAG = 'VeilStore';

/** AppStorage keys shared by every screen (and written optimistically on tap). */
export const K_STATUS: string = 'veilStatus';
export const K_MODE: string = 'veilMode';

/** Data the desktop card renders; field names must match VeilCard's props. */
export class CardData {
  phase: string = Phase.STOPPED;
  connected: boolean = false;
  node: string = '未选择节点';
  downRate: string = '—';
  upRate: string = '—';
  totalDown: string = '0 B';
  totalUp: string = '0 B';
  stateLabel: string = '未连接';
  accent: string = '#64748B';
  mode: string = 'rule';
  nodeCount: number = 0;
}

function labelOf(phase: string): string {
  if (phase === Phase.RUNNING) {
    return '已连接';
  }
  if (phase === Phase.DEGRADED) {
    return '已降级';
  }
  if (phase === Phase.STARTING) {
    return '连接中';
  }
  if (phase === Phase.STOPPING) {
    return '断开中';
  }
  if (phase === Phase.FAILED) {
    return '失败';
  }
  return '未连接';
}

function accentOf(phase: string): string {
  if (phase === Phase.RUNNING) {
    return '#5EEAD4';
  }
  if (phase === Phase.DEGRADED) {
    return '#FBBF24';
  }
  if (phase === Phase.STARTING || phase === Phase.STOPPING) {
    return '#818CF8';
  }
  if (phase === Phase.FAILED) {
    return '#F87171';
  }
  return '#64748B';
}

/**
 * Store — one source of truth for status/mode across every screen.
 *
 * Screens read `@StorageProp(K_MODE)` / `@StorageProp(K_STATUS)` instead of
 * keeping their own copies, so a mode switch on the rules tab is visible on the
 * home tab immediately. Writes are optimistic (state changes on tap, rollback on
 * error) and every successful write also refreshes the desktop cards.
 */
export class Store {
  private static inst: Store | null = null;

  static get(): Store {
    if (Store.inst === null) {
      Store.inst = new Store();
    }
    return Store.inst;
  }

  /** Pulls status once and publishes it. */
  async refresh(): Promise<Status | null> {
    try {
      const s: Status = await CoreClient.get().status();
      AppStorage.setOrCreate(K_STATUS, s);
      AppStorage.setOrCreate(K_MODE, s.mode);
      return s;
    } catch (err) {
      return null;
    }
  }

  /** Optimistically sets the mode locally, then confirms with the core. */
  async setMode(mode: string): Promise<void> {
    const prev: string = AppStorage.get<string>(K_MODE) as string;
    AppStorage.setOrCreate(K_MODE, mode);
    try {
      const s: Status = await CoreClient.get().setMode(mode);
      AppStorage.setOrCreate(K_STATUS, s);
      AppStorage.setOrCreate(K_MODE, s.mode);
      this.pushCards(s);
    } catch (err) {
      AppStorage.setOrCreate(K_MODE, prev);
      throw err as Error;
    }
  }

  /** Switches the active node and publishes the refreshed status. */
  async select(group: string, tag: string): Promise<void> {
    await CoreClient.get().select(group, tag);
    const fresh: Status | null = await this.refresh();
    if (fresh !== null) {
      this.pushCards(fresh);
    }
  }

  async start(): Promise<void> {
    try {
      await CoreClient.get().start();
    } catch (err) {
      await this.refresh();
      throw err as Error;
    }
    const s: Status | null = await this.refresh();
    if (s !== null) {
      this.pushCards(s);
    }
  }

  async stop(): Promise<void> {
    try {
      await CoreClient.get().stop();
    } catch (err) {
      await this.refresh();
      throw err as Error;
    }
    const s: Status | null = await this.refresh();
    if (s !== null) {
      this.pushCards(s);
    }
  }

  /** Rotates to the next member of the group holding the active node. */
  async rotateNode(): Promise<void> {
    const s: Status = await CoreClient.get().status();
    for (let i = 0; i < s.groups.length; i++) {
      const g = s.groups[i];
      if (g.members.length === 0) {
        continue;
      }
      let idx: number = 0;
      for (let j = 0; j < g.members.length; j++) {
        if (g.members[j].tag === g.now) {
          idx = j;
          break;
        }
      }
      const next = g.members[(idx + 1) % g.members.length];
      await this.select(g.tag, next.tag);
      return;
    }
  }

  /** Pushes the current state into every desktop card (best effort). */
  async pushCards(s: Status): Promise<void> {
    try {
      // Form ids are only known to the extension, which records them in the
      // shared preferences store; this process reads them back.
      const ctx: common.UIAbilityContext | null = CoreClient.get().abilityContext();
      if (ctx === null) {
        return;
      }
      const store = await preferences.getPreferences(ctx, 'veil_cards');
      const raw: string = await store.get('formIds', '[]') as string;
      const ids: string[] = JSON.parse(raw) as string[];
      if (ids.length === 0) {
        return;
      }
      const data: CardData = new CardData();
      const active: boolean = Phase.isActive(s.phase);
      data.phase = s.phase;
      data.connected = active;
      data.stateLabel = labelOf(s.phase);
      data.accent = accentOf(s.phase);
      data.downRate = formatRate(s.traffic.down_rate);
      data.upRate = formatRate(s.traffic.up_rate);
      data.totalDown = formatBytes(s.traffic.down);
      data.totalUp = formatBytes(s.traffic.up);
      data.mode = s.mode.length > 0 ? s.mode : 'rule';
      for (let i = 0; i < s.groups.length; i++) {
        if (s.groups[i].now.length > 0) {
          data.node = s.groups[i].now;
        }
        data.nodeCount += s.groups[i].members.length;
      }
      // Keep the snapshot the card renders on first show (it reads this
      // synchronously in onAddForm).
      try {
        const store = await preferences.getPreferences(ctx, 'veil_cards');
        await store.put('lastData', JSON.stringify(data));
        await store.flush();
      } catch (err) {
        hilog.debug(0x00FF, TAG, 'cache card data: %{public}s', String(err));
      }
      const bd: formBindingData.FormBindingData = formBindingData.createFormBindingData(data);
      for (let i = 0; i < ids.length; i++) {
        try {
          await formProvider.updateForm(ids[i], bd);
        } catch (err) {
          hilog.debug(0x00FF, TAG, 'updateForm %{public}s: %{public}s', ids[i], String(err));
        }
      }
    } catch (err) {
      hilog.debug(0x00FF, TAG, 'pushCards: %{public}s', String(err));
    }
  }
}
