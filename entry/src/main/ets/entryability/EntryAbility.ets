import { AbilityConstant, UIAbility, Want } from '@kit.AbilityKit';
import { window } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CoreClient } from '../core/CoreClient';

const TAG = 'Veil';

export default class EntryAbility extends UIAbility {
  private autoConnect: boolean = false;

  onCreate(want: Want, _launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(0x0000, TAG, 'ability created');
    // The desktop card can open the app with autoConnect=1 when it cannot start
    // the VPN extension from the form process; connect as soon as core is ready.
    const params: Record<string, Object> | undefined = want.parameters;
    if (params !== undefined) {
      const flag: Object | undefined = params['autoConnect'];
      this.autoConnect = flag !== undefined && String(flag) === '1';
    }
    // The UI process only needs the socket path and the bundle name; it never
    // touches the native library.
    CoreClient.get().init(this.context);
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(0x0000, TAG, 'loadContent failed: %{public}s', JSON.stringify(err));
      }
    });
  }

  onForeground(): void {
    // Coming back from background: the extension may have been killed while we
    // were away, so re-verify instead of trusting the previous connection.
    CoreClient.get().bootstrap().then((ok: boolean) => {
      if (!this.autoConnect || !ok) {
        return;
      }
      this.autoConnect = false;
      hilog.info(0x0000, TAG, 'auto-connect requested by the card');
      CoreClient.get().start().catch((e: Error) => {
        hilog.warn(0x0000, TAG, 'auto-connect failed: %{public}s', e.message);
      });
    }).catch((e: Error) => {
      hilog.warn(0x0000, TAG, 'bootstrap on foreground failed: %{public}s', e.message);
    });
  }

  onDestroy(): void {
    hilog.info(0x0000, TAG, 'ability destroyed');
    CoreClient.get().shutdown();
  }
}
