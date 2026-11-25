import { useEffect, useRef } from 'react';

/**
 * 克制星光缓漂粒子画布（低密度 + 柔和亮度 + 慢速漂浮，支持 prefers-reduced-motion）
 */
export default function Starfield() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let rafId = 0;
    let width = 0;
    let height = 0;
    let pointerX = 0;
    let pointerY = 0;

    interface Star {
      x: number;
      y: number;
      r: number;
      baseAlpha: number;
      phase: number;
      twinkleSpeed: number;
      swayPhase: number;
      swaySpeed: number;
      swayAmp: number;
      vy: number;
      depth: number;
      isSparkle: boolean;
      isGlowMote: boolean;
      color: string;
    }

    let stars: Star[] = [];
    const palette = ['59,130,246', '96,165,250', '56,189,248', '147,197,253'];

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const count = Math.min(Math.max(Math.floor((width * height) / 18000), 58), 95);
      stars = Array.from({ length: count }, (_, idx) => {
        const isSparkle = idx < 5;
        const isGlowMote = !isSparkle && idx < 20;
        return {
          x: Math.random() * width,
          y: Math.random() * height,
          r: isSparkle ? 1.0 + Math.random() * 0.55 : isGlowMote ? 0.85 + Math.random() * 0.6 : 0.5 + Math.random() * 0.65,
          baseAlpha: isSparkle ? 0.28 + Math.random() * 0.16 : isGlowMote ? 0.18 + Math.random() * 0.14 : 0.12 + Math.random() * 0.16,
          phase: Math.random() * Math.PI * 2,
          twinkleSpeed: 0.005 + Math.random() * 0.009,
          swayPhase: Math.random() * Math.PI * 2,
          swaySpeed: 0.003 + Math.random() * 0.006,
          swayAmp: 0.04 + Math.random() * 0.08,
          vy: -(0.035 + Math.random() * 0.075),
          depth: isSparkle ? 0.9 : isGlowMote ? 0.6 : 0.3,
          isSparkle,
          isGlowMote,
          color: palette[Math.floor(Math.random() * palette.length)],
        };
      });
    };

    const onMouseMove = (e: MouseEvent) => {
      pointerX = (e.clientX / Math.max(width, 1) - 0.5) * 2;
      pointerY = (e.clientY / Math.max(height, 1) - 0.5) * 2;
    };

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      for (const s of stars) {
        if (!reduceMotion) {
          s.phase += s.twinkleSpeed;
          s.swayPhase += s.swaySpeed;
          s.y += s.vy;
          s.x += Math.sin(s.swayPhase) * s.swayAmp;
          if (s.y < -10) {
            s.y = height + 10;
            s.x = Math.random() * width;
          }
          if (s.x < -10) s.x = width + 10;
          if (s.x > width + 10) s.x = -10;
        }
        const alpha = s.baseAlpha * (0.58 + 0.42 * Math.sin(s.phase));
        const px = s.x + pointerX * s.depth * 5;
        const py = s.y + pointerY * s.depth * 5;

        if (s.isSparkle || s.isGlowMote) {
          const glowR = s.isSparkle ? s.r * 3.4 : s.r * 2.6;
          const grad = ctx.createRadialGradient(px, py, 0, px, py, glowR);
          grad.addColorStop(0, `rgba(${s.color}, ${(alpha * 0.42).toFixed(3)})`);
          grad.addColorStop(1, `rgba(${s.color}, 0)`);
          ctx.fillStyle = grad;
          ctx.beginPath();
          ctx.arc(px, py, glowR, 0, Math.PI * 2);
          ctx.fill();
        }

        if (s.isSparkle) {
          const arm = s.r * 2.3;
          ctx.strokeStyle = `rgba(${s.color}, ${(alpha * 0.55).toFixed(3)})`;
          ctx.lineWidth = 0.65;
          ctx.beginPath();
          ctx.moveTo(px - arm, py);
          ctx.lineTo(px + arm, py);
          ctx.moveTo(px, py - arm);
          ctx.lineTo(px, py + arm);
          ctx.stroke();
        }

        ctx.beginPath();
        ctx.arc(px, py, s.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${s.color}, ${alpha.toFixed(3)})`;
        ctx.fill();
      }
      if (!reduceMotion) {
        rafId = window.requestAnimationFrame(draw);
      }
    };

    resize();
    draw();
    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', onMouseMove);
    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMouseMove);
      if (rafId) window.cancelAnimationFrame(rafId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="fixed inset-0 z-0 pointer-events-none"
    />
  );
}
