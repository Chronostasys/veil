/**
 * Glyph draws the small line icons used by the tab bar and the power button.
 *
 * Why Canvas and not Path/Shape: on device, ArkUI's Path interprets its SVG
 * commands in *pixels* and ignores the component box / viewPort scale, so a
 * 20-unit glyph renders as a ~6vp dot. Canvas is pixel-exact (the traffic
 * sparkline already proves it) and lets each glyph be drawn from the same
 * 20x20 design space at any size.
 */

export type GlyphKind = 'link' | 'nodes' | 'rules' | 'settings' | 'power';

@Component
export struct Glyph {
  @Prop kind: string = 'link';
  /** Concrete colour string: Canvas cannot resolve $r() resources. */
  @Prop tint: string = '#FFFFFF';
  @Prop dim: number = 22;
  @Prop weight: number = 1.6;

  private settings: RenderingContextSettings = new RenderingContextSettings(true);
  private ctx: CanvasRenderingContext2D = new CanvasRenderingContext2D(this.settings);

  build() {
    Canvas(this.ctx)
      .width(this.dim)
      .height(this.dim)
      .onReady(() => {
        this.draw();
      })
  }

  private draw(): void {
    const px: number = this.ctx.width;
    if (px <= 0) {
      return;
    }
    // 20x20 design space -> component pixels.
    const s: number = px / 20;
    const ctx = this.ctx;
    ctx.clearRect(0, 0, px, px);
    ctx.strokeStyle = this.tint;
    ctx.fillStyle = this.tint;
    ctx.lineWidth = this.weight * s;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    switch (this.kind) {
      case 'power':
        // Ring with a gap at the top plus the stem.
        ctx.beginPath();
        ctx.arc(10 * s, 10.6 * s, 6.4 * s, -Math.PI / 2 + 0.62, -Math.PI / 2 - 0.62 + Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(10 * s, 3.2 * s);
        ctx.lineTo(10 * s, 9.6 * s);
        ctx.stroke();
        break;

      case 'nodes':
        // A server list: three rows with a bullet on the left.
        for (let i = 0; i < 3; i++) {
          const y: number = (5.5 + i * 4.5) * s;
          ctx.beginPath();
          ctx.arc(3.6 * s, y, 1.15 * s, 0, Math.PI * 2);
          ctx.fill();
          ctx.beginPath();
          ctx.moveTo(7.2 * s, y);
          ctx.lineTo((16.4 - i * 1.6) * s, y);
          ctx.stroke();
        }
        break;

      case 'rules':
        // A routing tree: one trunk, two branches with end points.
        ctx.beginPath();
        ctx.moveTo(4.4 * s, 4 * s);
        ctx.lineTo(4.4 * s, 16 * s);
        ctx.stroke();
        for (let i = 0; i < 2; i++) {
          const y: number = (6.4 + i * 7.2) * s;
          ctx.beginPath();
          ctx.moveTo(4.4 * s, y);
          ctx.lineTo(13.6 * s, y);
          ctx.stroke();
          ctx.beginPath();
          ctx.arc(15.8 * s, y, 1.25 * s, 0, Math.PI * 2);
          ctx.fill();
        }
        break;

      case 'settings':
        // Sliders: three tracks with handles at different positions.
        for (let i = 0; i < 3; i++) {
          const y: number = (5.4 + i * 4.6) * s;
          ctx.beginPath();
          ctx.moveTo(3.4 * s, y);
          ctx.lineTo(16.6 * s, y);
          ctx.stroke();
        }
        ctx.beginPath();
        ctx.arc(12.6 * s, 5.4 * s, 1.7 * s, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(7.2 * s, 10 * s, 1.7 * s, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(11.4 * s, 14.6 * s, 1.7 * s, 0, Math.PI * 2);
        ctx.fill();
        break;

      case 'link':
      default:
        // A globe: outer ring, meridian ellipse, equator.
        ctx.beginPath();
        ctx.arc(10 * s, 10 * s, 6.9 * s, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.ellipse(10 * s, 10 * s, 3.1 * s, 6.9 * s, 0, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(3.1 * s, 10 * s);
        ctx.lineTo(16.9 * s, 10 * s);
        ctx.stroke();
        break;
    }
  }
}
