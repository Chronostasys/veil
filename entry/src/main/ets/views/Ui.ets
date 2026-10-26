import { ThemeColors, themeOf } from '../theme/Theme';

/**
 * Small shared atoms. Everything here is deliberately plain ArkUI — no images,
 * no icon font, no emoji. Shapes are drawn or expressed with hairlines.
 */

/** A pill used for modes, rule types and actions. */
@Component
export struct Chip {
  @Prop label: string = '';
  @Prop active: boolean = false;
  @Prop tone: string = '#5EEAD4';
  @State private pressed: boolean = false;
  onTap: () => void = () => {
  };

  build() {
    Text(this.label)
      .fontSize(12)
      .fontWeight(this.active ? FontWeight.Medium : FontWeight.Regular)
      .fontColor(this.active ? this.tone : $r('app.color.veil_text_dim'))
      .padding({ left: 12, right: 12, top: 6, bottom: 6 })
      .borderRadius(10)
      .backgroundColor(this.active ? $r('app.color.veil_surface_alt') :
        (this.pressed ? $r('app.color.veil_surface') : Color.Transparent))
      .border({
        width: this.active ? 1 : 0.5,
        color: this.active ? this.tone : $r('app.color.veil_hairline')
      })
      .scale({ x: this.pressed ? 0.94 : 1, y: this.pressed ? 0.94 : 1 })
      .animation({ duration: 120, curve: Curve.Sharp })
      .onTouch((event: TouchEvent) => {
        // Immediate tactile feedback: the chip shrinks on touch-down, long
        // before any RPC round-trip finishes.
        if (event.type === TouchType.Down) {
          this.pressed = true;
        } else if (event.type === TouchType.Up || event.type === TouchType.Cancel) {
          this.pressed = false;
        }
      })
      .onClick(() => {
        this.onTap();
      })
  }
}

/** Read-only label/value pill (e.g. node type, subscription state). */
@Component
export struct Tag {
  @Prop label: string = '';
  @Prop tone: string = '#8B94A5';

  build() {
    Text(this.label)
      .fontSize(10)
      .fontColor(this.tone)
      .padding({ left: 6, right: 6, top: 2, bottom: 2 })
      .borderRadius(6)
      .border({ width: 0.5, color: this.tone })
      .maxLines(1)
  }
}

/** Hairline separator; 1px at any density thanks to vp rounding. */
@Component
export struct Hairline {
  @Prop inset: number = 0;

  build() {
    Divider()
      .strokeWidth(0.5)
      .color($r('app.color.veil_hairline'))
      .margin({ left: this.inset, right: this.inset })
  }
}

/** Section title with an optional trailing action. */
@Component
export struct SectionTitle {
  @Prop title: string = '';
  @Prop action: string = '';
  onAction: () => void = () => {
  };

  build() {
    Row() {
      Text(this.title)
        .fontSize(13)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.veil_text_dim'))
        .letterSpacing(0.4)
      Blank()
      if (this.action.length > 0) {
        Text(this.action)
          .fontSize(12)
          .fontColor($r('app.color.veil_teal'))
          .onClick(() => {
            this.onAction();
          })
      }
    }
    .width('100%')
    .padding({ top: 4, bottom: 4 })
  }
}

/** Neutral empty/placeholder state. Never claims "connected". */
@Component
export struct EmptyBlock {
  @Prop title: string = '';
  @Prop subtitle: string = '';
  @Prop action: string = '';
  onAction: () => void = () => {
  };

  build() {
    Column({ space: 8 }) {
      // A quiet drawn mark instead of an icon: two hairlines forming a veil.
      Column() {
        Divider().strokeWidth(1).color($r('app.color.veil_hairline')).width(40)
        Divider().strokeWidth(1).color($r('app.color.veil_hairline')).width(28).margin({ top: 6 })
      }
      .margin({ bottom: 6 })

      Text(this.title)
        .fontSize(14)
        .fontColor($r('app.color.veil_text_dim'))
      if (this.subtitle.length > 0) {
        Text(this.subtitle)
          .fontSize(12)
          .fontColor($r('app.color.veil_text_faint'))
          .textAlign(TextAlign.Center)
          .maxLines(3)
      }
      if (this.action.length > 0) {
        Text(this.action)
          .fontSize(13)
          .fontColor($r('app.color.veil_teal'))
          .padding({ left: 16, right: 16, top: 8, bottom: 8 })
          .margin({ top: 4 })
          .borderRadius(10)
          .border({ width: 0.5, color: $r('app.color.veil_hairline') })
          .onClick(() => {
            this.onAction();
          })
      }
    }
    .width('100%')
    .padding({ top: 40, bottom: 40, left: 24, right: 24 })
    .alignItems(HorizontalAlign.Center)
  }
}

/** Label / value row used all over the settings screen. */
@Component
export struct KeyValueRow {
  @Prop label: string = '';
  @Prop value: string = '';
  @Prop tone: string = '#8B94A5';

  build() {
    Row() {
      Text(this.label)
        .fontSize(13)
        .fontColor($r('app.color.veil_text_dim'))
      Blank()
      Text(this.value)
        .fontSize(13)
        .fontColor(this.tone)
        .fontFeature('"tnum" 1')
        .textAlign(TextAlign.End)
        .maxLines(2)
    }
    .width('100%')
    .padding({ top: 10, bottom: 10 })
  }
}

/** Card container: 22vp radius, hairline border, one level of elevation. */
@Component
export struct Card {
  @Prop pad: number = 18;
  @BuilderParam content: () => void;

  build() {
    Column() {
      this.content()
    }
    .width('100%')
    .padding(this.pad)
    .borderRadius(22)
    .backgroundColor($r('app.color.veil_surface'))
    .border({ width: 0.5, color: $r('app.color.veil_hairline') })
  }
}

export function cardColors(dark: boolean): ThemeColors {
  return themeOf(dark);
}
