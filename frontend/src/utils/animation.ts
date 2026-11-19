// ============ 动画工具函数 ============

// 数字滚动动画
export function animateNumber(
  start: number,
  end: number,
  duration: number,
  onUpdate: (value: number) => void
): void {
  const startTime = performance.now();
  const step = (currentTime: number) => {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeProgress = 1 - Math.pow(1 - progress, 3); // ease-out-cubic
    const current = Math.floor(start + (end - start) * easeProgress);
    onUpdate(current);
    if (progress < 1) {
      requestAnimationFrame(step);
    }
  };
  requestAnimationFrame(step);
}

// 打字机效果
export function typewriter(
  text: string,
  speed: number,
  onUpdate: (partial: string) => void,
  onComplete?: () => void
): () => void {
  let index = 0;
  let cancelled = false;

  const type = () => {
    if (cancelled || index >= text.length) {
      if (!cancelled && onComplete) onComplete();
      return;
    }
    index++;
    onUpdate(text.slice(0, index));
    setTimeout(type, speed);
  };

  type();

  return () => {
    cancelled = true;
  };
}

// 滚动到元素并高亮
export function scrollToHighlight(elementId: string, duration: number = 2000): void {
  const element = document.getElementById(elementId);
  if (!element) return;

  element.scrollIntoView({ behavior: 'smooth', block: 'center' });
  element.classList.add('ring-2', 'ring-soc-primary', 'ring-offset-2', 'ring-offset-soc-bg');

  setTimeout(() => {
    element.classList.remove('ring-2', 'ring-soc-primary', 'ring-offset-2', 'ring-offset-soc-bg');
  }, duration);
}
