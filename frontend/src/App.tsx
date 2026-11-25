import {
  Component,
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useState,
  useTransition,
  type ReactNode,
} from 'react';
import {
  PanelLeftClose,
  PanelLeftOpen,
  Menu,
  X,
  RefreshCw,
  AlertTriangle,
  Plus,
  Trash2,
  Search,
} from 'lucide-react';
import { isMockMode, getHealth } from './api/client';
import type { HealthResponse } from './types/contract';
import {
  getSessions,
  getCurrentSessionId,
  createSession,
  getSession,
  deleteSession,
  setCurrentSessionId,
  type Session,
} from './utils/storage';
import AskTab from './components/AskTab';
import ToastContainer from './components/Toast';
import Starfield from './components/Starfield';
import CommandPalette, { type WorkspaceTab } from './components/CommandPalette';
import { Button } from './components/ui/Button';
import {
  AegisLogo,
  NavAskIcon,
  NavStatsIcon,
  NavMonitorIcon,
} from './components/ui/BrandIcons';

const StatsTab = lazy(() => import('./components/StatsTab'));
const MonitorTab = lazy(() => import('./components/MonitorTab'));

const NAV_META: Record<WorkspaceTab, { label: string; desc: string; shortcut: string }> = {
  ask: {
    label: '智能问答',
    desc: 'CVE 点查 · 语义检索 · 缝合溯源 · 编号级防幻觉',
    shortcut: '⌘1',
  },
  stats: {
    label: '数据看板',
    desc: '知识库资产分布 · 漏洞分类下钻 · 每日入库趋势',
    shortcut: '⌘2',
  },
  monitor: {
    label: '情报监测',
    desc: '多源采集调度 · 运行历史监控 · 手动增量触发',
    shortcut: '⌘3',
  },
};

function TabFallback() {
  return (
    <div className="flex items-center justify-center h-96">
      <div className="flex items-center gap-2.5 text-xs font-mono text-soc-text-muted">
        <span className="soc-dots">
          <span />
          <span />
          <span />
        </span>
        LOADING MODULE...
      </div>
    </div>
  );
}

class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (this.state.failed) {
      return (
        <div className="flex flex-col items-center justify-center h-96 gap-4 animate-fade-in">
          <p className="text-sm text-soc-text-secondary">
            页面组件加载出错（可能是构建产物已更新），请刷新重试
          </p>
          <Button variant="primary" onClick={() => window.location.reload()}>
            刷新页面
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const [activeTab, setActiveTabState] = useState<WorkspaceTab>('ask');
  const [, startTransition] = useTransition();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [backendDown, setBackendDown] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(
    () => localStorage.getItem('aegis.sidebarCollapsed') === '1'
  );
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [cmdOpen, setCmdOpen] = useState(false);

  // 统一会话状态：单侧栏直接展示会话列表，彻底消除双侧栏割裂感
  const [sessions, setSessions] = useState<Session[]>([]);
  const [currentSessionId, setCurrentSessionState] = useState<string | null>(null);
  // 跨页面联动：看板下钻 / ⌘K 发起的待研判问题
  const [pendingQuery, setPendingQuery] = useState<{ id: number; query: string } | null>(null);

  const refreshSessions = useCallback(() => {
    setSessions(getSessions());
  }, []);

  const handleCreateSession = useCallback(() => {
    const created = createSession();
    setSessions(getSessions());
    setCurrentSessionState(created.id);
    setActiveTabState('ask');
    return created.id;
  }, []);

  const handleSelectSession = useCallback((id: string) => {
    setCurrentSessionState(id);
    setCurrentSessionId(id);
    setActiveTabState('ask');
    setMobileNavOpen(false);
  }, []);

  const handleDeleteSession = useCallback(
    (id: string) => {
      deleteSession(id);
      const remaining = getSessions();
      setSessions(remaining);
      if (currentSessionId === id) {
        if (remaining.length > 0) {
          setCurrentSessionState(remaining[0].id);
          setCurrentSessionId(remaining[0].id);
        } else {
          handleCreateSession();
        }
      }
    },
    [currentSessionId, handleCreateSession]
  );

  useEffect(() => {
    const existing = getSessions();
    setSessions(existing);
    const savedId = getCurrentSessionId();
    if (savedId && getSession(savedId)) {
      setCurrentSessionState(savedId);
    } else if (existing.length > 0) {
      setCurrentSessionState(existing[0].id);
      setCurrentSessionId(existing[0].id);
    } else {
      handleCreateSession();
    }
  }, [handleCreateSession]);

  const setActiveTab = useCallback((key: WorkspaceTab) => {
    setMobileNavOpen(false);
    startTransition(() => setActiveTabState(key));
  }, []);

  const launchInvestigation = useCallback((query: string) => {
    setActiveTabState('ask');
    setPendingQuery({ id: Date.now(), query });
  }, []);

  const handleInvestigateCVE = useCallback(
    (cveId: string) => {
      launchInvestigation(`${cveId} 是什么漏洞？受影响组件和修复建议是什么？`);
    },
    [launchInvestigation]
  );

  // 全局快捷键：⌘K / Ctrl+K 打开命令面板，⌘1/2/3 切换模块
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCmdOpen((v) => !v);
      } else if ((e.metaKey || e.ctrlKey) && e.key === '1') {
        e.preventDefault();
        setActiveTab('ask');
      } else if ((e.metaKey || e.ctrlKey) && e.key === '2') {
        e.preventDefault();
        setActiveTab('stats');
      } else if ((e.metaKey || e.ctrlKey) && e.key === '3') {
        e.preventDefault();
        setActiveTab('monitor');
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [setActiveTab]);

  // 空闲预取其余 Tab
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void import('./components/StatsTab');
      void import('./components/MonitorTab');
    }, 1600);
    return () => window.clearTimeout(timer);
  }, []);

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

  const toggleSidebar = () => {
    setSidebarCollapsed((prev) => {
      localStorage.setItem('aegis.sidebarCollapsed', prev ? '0' : '1');
      return !prev;
    });
  };

  const mock = isMockMode();
  const activeMeta = NAV_META[activeTab];

  const renderNavButtons = (collapsed: boolean) => (
    <nav className="px-3 pt-2 pb-3 space-y-1" aria-label="主导航">
      {(['ask', 'stats', 'monitor'] as WorkspaceTab[]).map((key) => {
        const active = activeTab === key;
        return (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            title={collapsed ? NAV_META[key].label : undefined}
            className={`group relative w-full flex items-center gap-2.5 rounded-xl px-2.5 py-2 text-left transition-all ${
              active
                ? 'bg-white/[0.07] text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.09)]'
                : 'text-slate-400 hover:bg-white/[0.04] hover:text-slate-100'
            } ${collapsed ? 'justify-center px-0' : ''}`}
          >
            {active && !collapsed && (
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.9)]" />
            )}
            {key === 'ask' && <NavAskIcon active={active} />}
            {key === 'stats' && <NavStatsIcon active={active} />}
            {key === 'monitor' && <NavMonitorIcon active={active} />}
            {!collapsed && (
              <>
                <span className="text-[13px] font-medium flex-1 truncate">
                  {NAV_META[key].label}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {NAV_META[key].shortcut}
                </span>
              </>
            )}
          </button>
        );
      })}
    </nav>
  );

  return (
    <div className="relative h-screen flex overflow-hidden bg-soc-bg text-soc-text-primary aegis-ambient-bg">
      <Starfield />
      <div className="film-noise" aria-hidden="true" />

      {/* Unified Desktop Sidebar */}
      <aside
        className={`relative z-10 hidden md:flex flex-col flex-shrink-0 bg-[#07090f]/75 backdrop-blur-xl border-r border-white/[0.06] transition-[width] duration-200 ${
          sidebarCollapsed ? 'w-16' : 'w-[248px]'
        }`}
      >
        <div
          className={`h-14 flex items-center px-4 ${
            sidebarCollapsed ? 'justify-center px-2' : 'justify-between'
          }`}
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-sky-500/20 via-indigo-500/15 to-cyan-400/15 border border-sky-300/30 flex items-center justify-center flex-shrink-0 shadow-[0_0_24px_-6px_rgba(56,189,248,0.65),inset_0_1px_0_rgba(255,255,255,0.28)]">
              <AegisLogo />
            </div>
            {!sidebarCollapsed && (
              <div className="min-w-0">
                <p className="text-[13.5px] font-semibold tracking-tight text-white truncate">
                  Aegis Intel
                </p>
                <p className="text-[10px] font-mono text-slate-400 tracking-wider truncate">
                  AI SECURITY
                </p>
              </div>
            )}
          </div>
          {!sidebarCollapsed && (
            <button
              onClick={toggleSidebar}
              aria-label="收起侧边栏"
              className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-white/[0.06] transition-colors"
            >
              <PanelLeftClose size={14} />
            </button>
          )}
        </div>

        {renderNavButtons(sidebarCollapsed)}

        {!sidebarCollapsed && (
          <>
            <div className="mx-4 my-1 h-px bg-gradient-to-r from-transparent via-white/[0.08] to-transparent" />
            <div className="flex-1 flex flex-col min-h-0 px-3 pt-2.5">
              <div className="flex items-center justify-between px-1.5 mb-2">
                <span className="text-[10px] font-mono uppercase tracking-widest text-slate-500">
                  研判会话
                </span>
                <button
                  onClick={handleCreateSession}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/[0.05] hover:bg-white/[0.1] text-[11px] text-slate-300 hover:text-white transition-colors"
                >
                  <Plus size={11} className="text-sky-400" />
                  新建
                </button>
              </div>
              <div className="flex-1 overflow-y-auto space-y-0.5 pr-0.5">
                {sessions.map((s) => {
                  const active = s.id === currentSessionId && activeTab === 'ask';
                  return (
                    <div
                      key={s.id}
                      onClick={() => handleSelectSession(s.id)}
                      className={`group flex items-start justify-between gap-2 px-2.5 py-2 rounded-lg cursor-pointer transition-colors ${
                        active
                          ? 'bg-white/[0.07] text-white'
                          : 'text-slate-400 hover:bg-white/[0.03] hover:text-slate-200'
                      }`}
                    >
                      <div className="min-w-0 flex-1">
                        <p className={`text-xs truncate ${active ? 'font-medium' : ''}`}>
                          {s.title}
                        </p>
                        <p className="text-[10px] text-slate-500 font-mono tabular-nums mt-0.5">
                          {s.messages.length} 条 · {new Date(s.createdAt).toLocaleDateString()}
                        </p>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleDeleteSession(s.id);
                        }}
                        aria-label={`删除会话 ${s.title}`}
                        className="opacity-0 group-hover:opacity-100 p-1 rounded text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}

        <div className="p-3 border-t border-white/[0.05] mt-auto">
          {sidebarCollapsed ? (
            <button
              onClick={toggleSidebar}
              aria-label="展开侧边栏"
              className="w-full h-8 flex items-center justify-center rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors"
            >
              <PanelLeftOpen size={15} />
            </button>
          ) : (
            <div className="rounded-xl bg-white/[0.025] border border-white/[0.06] px-3 py-2.5 space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                {mock ? (
                  <span className="text-amber-300 font-mono text-[10px]">MOCK 演示模式</span>
                ) : backendDown ? (
                  <button
                    onClick={probe}
                    className="text-rose-400 hover:underline font-medium"
                  >
                    ● 后端离线 · 重试
                  </button>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-emerald-300 font-medium">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    引擎在线
                  </span>
                )}
                {!mock && health?.status === 'ok' && (
                  <span className="font-mono text-[10px] text-slate-300 tabular-nums">
                    {health.store_count.toLocaleString()} 块
                  </span>
                )}
              </div>
              {!mock && health?.model && (
                <p className="text-[10px] font-mono text-slate-500 truncate" title={health.model}>
                  {health.model}
                </p>
              )}
            </div>
          )}
        </div>
      </aside>

      {/* Mobile Drawer */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div className="fixed inset-0 bg-black/75" onClick={() => setMobileNavOpen(false)} />
          <aside className="relative z-10 w-64 max-w-[80vw] bg-[#07090f] border-r border-white/[0.08] flex flex-col">
            <div className="h-14 flex items-center justify-between px-4 border-b border-white/[0.06]">
              <span className="text-sm font-semibold text-white">Aegis Intel</span>
              <button
                onClick={() => setMobileNavOpen(false)}
                className="p-1 text-slate-400 hover:text-white"
              >
                <X size={16} />
              </button>
            </div>
            {renderNavButtons(false)}
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        <header className="h-13 flex-shrink-0 px-5 py-2.5 flex items-center justify-between gap-4 border-b border-white/[0.05] bg-[#05060a]/45 backdrop-blur-md">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => setMobileNavOpen(true)}
              aria-label="打开导航"
              className="md:hidden p-1.5 -ml-1 rounded-lg text-slate-300 hover:bg-white/[0.06]"
            >
              <Menu size={16} />
            </button>
            <div className="flex items-center gap-2.5 min-w-0">
              <span className="text-[13px] font-semibold text-white whitespace-nowrap">
                {activeMeta.label}
              </span>
              <span className="text-white/15 hidden sm:inline">·</span>
              <span className="text-xs text-slate-400 truncate hidden sm:inline">
                {activeMeta.desc}
              </span>
            </div>
          </div>

          <button
            onClick={() => setCmdOpen(true)}
            className="h-7 px-3 rounded-full bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.09] text-[11px] text-slate-300 inline-flex items-center gap-2 transition-colors flex-shrink-0"
          >
            <Search size={12} className="text-sky-400" />
            <span className="hidden sm:inline">快捷命令</span>
            <kbd className="font-mono text-[10px] text-slate-400">⌘K</kbd>
          </button>
        </header>

        {backendDown && (
          <div className="flex-shrink-0 px-5 pt-3">
            <div className="rounded-xl bg-rose-500/10 border border-rose-500/35 px-4 py-2.5 text-xs flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-rose-200 min-w-0">
                <AlertTriangle size={14} className="flex-shrink-0 text-rose-400" />
                <span className="truncate">
                  无法连接后端 (127.0.0.1:8000)，请先运行{' '}
                  <code className="px-1.5 py-0.5 rounded bg-black/40 font-mono text-rose-100">
                    uv run python scripts/api.py
                  </code>
                </span>
              </div>
              <Button variant="danger" size="xs" onClick={probe}>
                <RefreshCw size={12} />
                重试
              </Button>
            </div>
          </div>
        )}

        <main
          className={`flex-1 min-h-0 ${
            activeTab === 'ask' ? 'overflow-hidden' : 'overflow-y-auto px-5 sm:px-8 py-6'
          }`}
        >
          <AppErrorBoundary>
            <Suspense fallback={<TabFallback />}>
              {activeTab === 'ask' && (
                <AskTab
                  sessions={sessions}
                  currentSessionId={currentSessionId}
                  onSessionsChange={refreshSessions}
                  onSelectSession={handleSelectSession}
                  onCreateSession={handleCreateSession}
                  pendingQuery={pendingQuery}
                  onConsumePendingQuery={() => setPendingQuery(null)}
                />
              )}
              {activeTab === 'stats' && <StatsTab onInvestigate={handleInvestigateCVE} />}
              {activeTab === 'monitor' && <MonitorTab />}
            </Suspense>
          </AppErrorBoundary>
        </main>
      </div>

      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        sessions={sessions}
        onSwitchTab={setActiveTab}
        onSelectSession={handleSelectSession}
        onNewSession={handleCreateSession}
        onQuickQuery={launchInvestigation}
      />

      <ToastContainer />
    </div>
  );
}

export default App;
