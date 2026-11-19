import { useEffect, useRef } from 'react';

// ============ 荧光粒子场 v3（精致小颗粒 + 发丝连线 + 星芒点缀）============
// 设计取向：小而锐利的点、极淡的氛围光斑、发丝级连线、少量四角星芒
// 三层景深 + 弧线漂移 + 鼠标视差；DPR 感知 / 隐藏暂停 / reduced-motion 静态帧
// 注意：canvas 必须保持透明，否则会盖住 .soc-bg-aura 渐晕与网格

interface Drifter {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  hue: number;
  phase: number;
  phaseSpeed: number;
  ampX: number;
  ampY: number;
  baseA: number;
  twinkleSpeed: number;
  twinklePhase: number;
}

interface Orb {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  alpha: number;
  sprite: HTMLCanvasElement;
  phase: number;
}

interface Sparkle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
  hue: number;
  baseA: number;
  speed: number;
  phase: number;
}

const HUES = [189, 189, 189, 210, 262]; // 青为主，蓝/紫点缀
const LINK_DIST = 118; // 更短连线距离 → 线条更少更干净

// 预渲染氛围光斑（极淡，仅作纵深，不抢主体）
function makeOrbSprite(hue: number): HTMLCanvasElement {
  const s = document.createElement('canvas');
  s.width = 256;
  s.height = 256;
  const c = s.getContext('2d');
  if (!c) return s;
  const g = c.createRadialGradient(128, 128, 0, 128, 128, 128);
  g.addColorStop(0, `hsla(${hue}, 88%, 60%, 0.34)`);
  g.addColorStop(0.45, `hsla(${hue}, 88%, 56%, 0.1)`);
  g.addColorStop(1, `hsla(${hue}, 88%, 52%, 0)`);
  c.fillStyle = g;
  c.fillRect(0, 0, 256, 256);
  return s;
}

export default function ParticleField() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let raf = 0;
    let w = 0;
    let h = 0;

    let main: Drifter[] = [];
    let dust: Drifter[] = [];
    let orbs: Orb[] = [];
    let sparkles: Sparkle[] = [];
    const sprites = [189, 210, 262].map(makeOrbSprite);

    const mouse = { tx: 0, ty: 0, x: 0, y: 0 };
    const pickHue = () => HUES[Math.floor(Math.random() * HUES.length)];

    const makeDrifter = (speed: number, rMin: number, rMax: number, aBase: number): Drifter => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * speed,
      vy: (Math.random() - 0.5) * speed,
      r: rMin + Math.random() * (rMax - rMin),
      hue: pickHue(),
      phase: Math.random() * Math.PI * 2,
      phaseSpeed: 0.003 + Math.random() * 0.005,
      ampX: 2 + Math.random() * 7,
      ampY: 2 + Math.random() * 6,
      baseA: aBase + Math.random() * 0.2,
      twinkleSpeed: 0.5 + Math.random() * 1.2,
      twinklePhase: Math.random() * Math.PI * 2,
    });

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth;
      h = window.innerHeight;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      // 粒子更少、更小 → 干净克制
      const mainCount = Math.min(64, Math.max(34, Math.floor((w * h) / 30000)));
      main = Array.from({ length: mainCount }, () => makeDrifter(0.22, 0.5, 1.25, 0.5));
      dust = Array.from({ length: Math.floor(mainCount * 0.35) }, () =>
        makeDrifter(0.46, 0.3, 0.65, 0.45)
      );
      orbs = Array.from({ length: 4 }, (_, i) => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.1,
        vy: (Math.random() - 0.5) * 0.1,
        size: 260 + Math.random() * 200,
        alpha: 0.35 + Math.random() * 0.3, // 叠乘 sprite 自带低透明度 → 总强度 ~4-8%
        sprite: sprites[i % sprites.length],
        phase: Math.random() * Math.PI * 2,
      }));
      // 四角星芒：设计感点缀（5 颗，克制）
      sparkles = Array.from({ length: 5 }, () => ({
        x: w * (0.08 + Math.random() * 0.84),
        y: h * (0.08 + Math.random() * 0.7),
        vx: (Math.random() - 0.5) * 0.14,
        vy: (Math.random() - 0.5) * 0.14,
        r: 2.2 + Math.random() * 1.4,
        hue: Math.random() < 0.7 ? 190 : 265,
        baseA: 0.35 + Math.random() * 0.2,
        speed: 0.4 + Math.random() * 0.7,
        phase: Math.random() * Math.PI * 2,
      }));
    };

    const wrap = (p: { x: number; y: number }, m: number) => {
      if (p.x < -m) p.x = w + m;
      else if (p.x > w + m) p.x = -m;
      if (p.y < -m) p.y = h + m;
      else if (p.y > h + m) p.y = -m;
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);

      mouse.x += (mouse.tx - mouse.x) * 0.045;
      mouse.y += (mouse.ty - mouse.y) * 0.045;

      // 层1：氛围光斑（极淡、缓慢，只做纵深）
      for (const o of orbs) {
        o.x += o.vx;
        o.y += o.vy;
        o.phase += 0.0016;
        wrap(o, o.size / 2);
        const ox = o.x - o.size / 2 - mouse.x * 16;
        const oy = o.y - o.size / 2 - mouse.y * 10 + Math.sin(o.phase) * 8;
        ctx.globalAlpha = o.alpha;
        ctx.drawImage(o.sprite, ox, oy, o.size, o.size);
      }

      // 层2：主粒子（小颗、锐利）
      const px: number[] = [];
      const py: number[] = [];
      const pa: number[] = [];
      for (let i = 0; i < main.length; i++) {
        const p = main[i];
        p.x += p.vx;
        p.y += p.vy;
        p.phase += p.phaseSpeed;
        wrap(p, 24);
        px[i] = p.x + Math.sin(p.phase) * p.ampX - mouse.x * 9;
        py[i] = p.y + Math.cos(p.phase * 0.82) * p.ampY - mouse.y * 7;
        const tw = Math.sin(t * p.twinkleSpeed + p.twinklePhase) * 0.24;
        pa[i] = Math.min(0.95, Math.max(0.16, p.baseA + tw));
      }

      // 发丝连线（单描边、低亮度，干净）
      for (let i = 0; i < main.length; i++) {
        for (let j = i + 1; j < main.length; j++) {
          const dx = px[i] - px[j];
          const dy = py[i] - py[j];
          const d2 = dx * dx + dy * dy;
          if (d2 >= LINK_DIST * LINK_DIST) continue;
          const d = Math.sqrt(d2);
          const a = (1 - d / LINK_DIST) * 0.17 * Math.min(pa[i], pa[j]);
          if (a < 0.015) continue;
          const hue = (main[i].hue + main[j].hue) / 2;
          ctx.strokeStyle = `hsla(${hue}, 85%, 72%, ${a.toFixed(3)})`;
          ctx.lineWidth = 0.75;
          ctx.beginPath();
          ctx.moveTo(px[i], py[i]);
          ctx.lineTo(px[j], py[j]);
          ctx.stroke();
        }
      }

      // 主粒子：极薄柔光 + 小锐芯（点状，不糊成球）
      for (let i = 0; i < main.length; i++) {
        const p = main[i];
        ctx.globalAlpha = pa[i] * 0.14;
        ctx.fillStyle = `hsl(${p.hue}, 92%, 64%)`;
        ctx.beginPath();
        ctx.arc(px[i], py[i], p.r * 2.6, 0, Math.PI * 2);
        ctx.fill();

        ctx.globalAlpha = pa[i];
        ctx.fillStyle = `hsl(${p.hue}, 70%, 86%)`;
        ctx.beginPath();
        ctx.arc(px[i], py[i], p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // 层3：前景微尘（反向视差）
      for (const p of dust) {
        p.x += p.vx;
        p.y += p.vy;
        p.phase += p.phaseSpeed;
        wrap(p, 16);
        const x = p.x + Math.sin(p.phase) * p.ampX + mouse.x * 14;
        const y = p.y + Math.cos(p.phase * 0.9) * p.ampY + mouse.y * 10;
        const a = Math.min(0.9, p.baseA + Math.sin(t * p.twinkleSpeed + p.twinklePhase) * 0.26);
        ctx.globalAlpha = a * 0.7;
        ctx.fillStyle = `hsl(${p.hue}, 60%, 90%)`;
        ctx.beginPath();
        ctx.arc(x, y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }

      // 星芒：细十字 + 中心点（缓慢呼吸）
      for (const s of sparkles) {
        s.x += s.vx;
        s.y += s.vy;
        wrap(s, 20);
        const a = Math.max(0.08, s.baseA + Math.sin(t * s.speed + s.phase) * 0.3);
        const x = s.x - mouse.x * 6;
        const y = s.y - mouse.y * 5;
        ctx.globalAlpha = a;
        ctx.strokeStyle = `hsla(${s.hue}, 90%, 88%, 0.9)`;
        ctx.lineWidth = 0.75;
        ctx.beginPath();
        ctx.moveTo(x - s.r * 2.2, y);
        ctx.lineTo(x + s.r * 2.2, y);
        ctx.moveTo(x, y - s.r * 2.2);
        ctx.lineTo(x, y + s.r * 2.2);
        ctx.stroke();
        ctx.fillStyle = `hsla(${s.hue}, 90%, 92%, 0.95)`;
        ctx.beginPath();
        ctx.arc(x, y, s.r * 0.42, 0, Math.PI * 2);
        ctx.fill();
      }

      ctx.globalAlpha = 1;
    };

    const step = () => {
      draw(performance.now() / 1000);
      raf = requestAnimationFrame(step);
    };

    resize();
    if (reduce) {
      draw(0);
    } else {
      raf = requestAnimationFrame(step);
    }

    const onResize = () => {
      resize();
      if (reduce) draw(0);
    };
    const onVisibility = () => {
      cancelAnimationFrame(raf);
      if (!document.hidden && !reduce) raf = requestAnimationFrame(step);
    };
    const onPointer = (e: PointerEvent) => {
      mouse.tx = (e.clientX / w - 0.5) * 2;
      mouse.ty = (e.clientY / h - 0.5) * 2;
    };

    window.addEventListener('resize', onResize);
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pointermove', onPointer, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pointermove', onPointer);
    };
  }, []);

  // 不设背景色：保持透明，让 .soc-bg-aura 渐晕与网格透出
  return <canvas ref={ref} className="fixed inset-0 z-0 pointer-events-none" aria-hidden />;
}
