import { Component, lazy, Suspense, useEffect, useState, useTransition, type ReactNode } from 'react';
import { isMockMode, getHealth } from './api/client';
import type { HealthResponse } from './types/contract';
import AskTab from './components/AskTab';
import ToastContainer from './components/Toast';
import ParticleField from './components/ParticleField';

// 看板与监测按需加载：首屏只加载问答链路
const StatsTab = lazy(() => import('./components/StatsTab'));
const MonitorTab = lazy(() => import('./components/MonitorTab'));

type Tab = 'ask' | 'stats' | 'monitor';

// 懒加载占位（与设计体系一致的荧光三点）
function TabFallback() {
  return (
    <div className="flex items-center justify-center h-96">
      <span className="soc-dots">
        <span />
        <span />
        <span />
      </span>
    </div>
  );
}

// 错误边界：兜住 chunk 加载失败 / 渲染异常，给出可恢复的出口
class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <div className="flex flex-col items-center justify-center h-96 gap-4 animate-panel-reveal">
          <p className="text-soc-text-secondary">
            页面组件加载出错（可能是构建产物已更新），请刷新重试
          </p>
          <button
            onClick={() => window.location.reload()}
            className="soc-btn-primary px-4 py-2 text-sm font-medium"
          >
            刷新页面
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const [activeTab, setActiveTabState] = useState<Tab>('ask');
  const [, startTransition] = useTransition();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [backendDown, setBackendDown] = useState(false);

  // React 18：lazy Tab 切换走 transition，避免同步 suspend 把整页替换成 loading
  const setActiveTab = (key: Tab) => {
    startTransition(() => setActiveTabState(key));
  };

  // 空闲预取其余 Tab 代码：点击切换零等待（文件小，仅多 14KB）
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void import('./components/StatsTab');
      void import('./components/MonitorTab');
    }, 1600);
    return () => window.clearTimeout(timer);
  }, []);

  // 真实模式启动探活 /health（mock 模式跳过）；后端未启动给明确指引
  const probe = () => {
    if (isMockMode()) return;
    getHealth()
      .then((h) => {
        setHealth(h);
        setBackendDown(false);
      })
      .catch(() => {
        setHealth(null);
        setBackendDown(true);
      });
  };

  useEffect(() => {
    probe();
  }, []);

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text-primary">
      {/* 背景层：荧光渐晕 + 辉光网格 + 粒子场 + 扫描线 */}
      <div className="soc-bg-aura" aria-hidden />
      <div className="soc-bg-grain" aria-hidden />
      <ParticleField />
      <div className="soc-scanline" aria-hidden />

      {/* 内容层 */}
      <div className="relative z-10">
        {/* Header：编辑部报头风（大衬线标题 + 星座线装饰） */}
        <header className="border-b border-soc-border/70 sticky top-0 z-30 bg-soc-bg/92 backdrop-blur-sm">
          <div className="container mx-auto px-8 py-6">
            <div className="flex items-center justify-between gap-6">
              <div className="min-w-0">
                <p className="text-[11px] tracking-[0.3em] uppercase text-soc-text-muted mb-2">
                  CHINA ELECTRONICS CUP · QIANXIN TRACK
                </p>
                <h1 className="text-2xl md:text-[27px] leading-tight font-semibold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-200 via-cyan-300 to-violet-300 [filter:drop-shadow(0_0_14px_rgba(34,211,238,0.35))] truncate">
                  智能体驱动的 AI 安全知识情报系统
                </h1>
                <div className="flex items-center gap-3 mt-3">
                  {/* 网络线装饰：绘制动画 + 节点脉动 */}
                  <svg width="132" height="12" viewBox="0 0 132 12" fill="none" className="flex-shrink-0">
                    <line
                      x1="4" y1="6" x2="128" y2="6"
                      stroke="#334155" strokeWidth="1"
                      className="soc-draw-line" style={{ ['--dash' as string]: '140' }}
                    />
                    <circle cx="4" cy="6" r="2" fill="#38bdf8" style={{ animation: 'node-pulse 3s ease-in-out infinite' }} />
                    <circle cx="66" cy="6" r="2" fill="#94a3b8" style={{ animation: 'node-pulse 3s ease-in-out 0.8s infinite' }} />
                    <circle cx="128" cy="6" r="2" fill="#38bdf8" style={{ animation: 'node-pulse 3s ease-in-out 1.6s infinite' }} />
                  </svg>
                  <p className="text-xs tracking-[0.14em] text-soc-text-secondary">
                    三模块流水线：监测 → 富化 → 问答
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {!isMockMode() &&
                  (backendDown ? (
                    <div className="px-3 py-1.5 border border-soc-danger/50 text-soc-danger text-xs font-mono tracking-wider">
                      后端未启动
                    </div>
                  ) : health?.status === 'ok' ? (
                    <div className="px-3 py-1.5 border border-soc-success/45 text-soc-success text-xs font-mono tracking-wider flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-soc-success animate-pulse" />
                      服务正常 · {health.store_count.toLocaleString()} 块
                    </div>
                  ) : null)}
                {isMockMode() && (
                  <div className="px-3 py-1.5 border border-soc-border text-soc-text-muted text-[11px] font-mono tracking-[0.2em]">
                    MOCK 数据
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        {/* 后端未启动提示条（真实模式） */}
        {backendDown && (
          <div className="container mx-auto px-8 pt-5">
            <div className="p-4 bg-soc-danger/10 border border-soc-danger/35 text-sm flex items-center justify-between gap-4 animate-panel-reveal">
              <span className="text-soc-danger">
                无法连接后端 (127.0.0.1:8000)，请先运行 <span className="font-mono">uv run python scripts/api.py</span>（首次启动模型加载约 40 秒）
              </span>
              <button onClick={probe} className="soc-btn-ghost px-3 py-1.5 text-xs flex-shrink-0">
                重新探测
              </button>
            </div>
          </div>
        )}

        {/* Tab Navigation：editorial 大写字距导航 */}
        <nav className="border-b border-soc-border/70 bg-soc-bg/80 backdrop-blur-sm">
          <div className="container mx-auto px-8">
            <div className="flex gap-10">
              {[
                { key: 'ask' as const, label: '智能问答', en: 'ASK' },
                { key: 'stats' as const, label: '数据看板', en: 'DASHBOARD' },
                { key: 'monitor' as const, label: '情报监测', en: 'MONITOR' },
              ].map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={`group relative py-4 text-sm tracking-[0.18em] transition-colors ${
                    activeTab === tab.key
                      ? 'text-soc-primary'
                      : 'text-soc-text-secondary hover:text-soc-text-primary'
                  }`}
                >
                  <span className="text-base mr-2.5 font-medium">{tab.label}</span>
                  <span className="text-[10px] font-mono tracking-[0.24em] opacity-60">{tab.en}</span>
                  {activeTab === tab.key && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-soc-primary animate-tab-underline" />
                  )}
                  {activeTab !== tab.key && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-soc-primary/40 scale-x-0 group-hover:scale-x-100 transition-transform duration-200 origin-left" />
                  )}
                </button>
              ))}
            </div>
          </div>
        </nav>

        {/* Tab Content */}
        <main className="container mx-auto px-8 py-8">
          <AppErrorBoundary>
            <Suspense fallback={<TabFallback />}>
              {activeTab === 'ask' && <AskTab />}
              {activeTab === 'stats' && <StatsTab />}
              {activeTab === 'monitor' && <MonitorTab />}
            </Suspense>
          </AppErrorBoundary>
        </main>

        {/* 应用内 Toast（全局挂载） */}
        <ToastContainer />
      </div>
    </div>
  );
}

export default App;
