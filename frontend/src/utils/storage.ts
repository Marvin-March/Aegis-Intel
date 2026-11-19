// ============ localStorage 会话管理 ============

export interface Session {
  id: string;
  title: string;
  createdAt: string;
  messages: Message[];
}

export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  response?: any; // AskResponse for assistant messages
}

// v2：api.py 契约切换（旧 v1 数据为旧契约形状，直接弃用避免渲染异常）
const STORAGE_KEY = 'intel_qa_sessions_v2';
const CURRENT_SESSION_KEY = 'intel_qa_current_session_v2';

export function getSessions(): Session[] {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function saveSessions(sessions: Session[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
  } catch {
    // 配额溢出：优先丢弃最旧会话后重试一次；仍失败则放弃写入，不阻断交互
    try {
      const trimmed = sessions.slice(0, Math.max(1, sessions.length - 1));
      localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    } catch {
      /* 忽略 */
    }
  }
}

export function getCurrentSessionId(): string | null {
  return localStorage.getItem(CURRENT_SESSION_KEY);
}

export function setCurrentSessionId(id: string): void {
  localStorage.setItem(CURRENT_SESSION_KEY, id);
}

export function createSession(): Session {
  const session: Session = {
    id: `session_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
    title: '新对话',
    createdAt: new Date().toISOString(),
    messages: [],
  };
  const sessions = getSessions();
  sessions.unshift(session);
  saveSessions(sessions);
  setCurrentSessionId(session.id);
  return session;
}

export function getSession(id: string): Session | undefined {
  return getSessions().find((s) => s.id === id);
}

export function updateSession(id: string, updates: Partial<Session>): void {
  const sessions = getSessions();
  const idx = sessions.findIndex((s) => s.id === id);
  if (idx !== -1) {
    sessions[idx] = { ...sessions[idx], ...updates };
    saveSessions(sessions);
  }
}

export function deleteSession(id: string): void {
  const sessions = getSessions().filter((s) => s.id !== id);
  saveSessions(sessions);
  if (getCurrentSessionId() === id) {
    localStorage.removeItem(CURRENT_SESSION_KEY);
  }
}

export function addMessage(sessionId: string, message: Message): void {
  const session = getSession(sessionId);
  if (session) {
    session.messages.push(message);
    // 自动生成标题（使用第一条用户消息）
    if (session.messages.length === 1 && message.role === 'user') {
      session.title = message.content.slice(0, 30) + (message.content.length > 30 ? '...' : '');
    }
    updateSession(sessionId, session);
  }
}

// 两段式问答：/search 先插入检索结果消息，/ask 返回后回填答案
export function updateMessage(sessionId: string, msgId: string, patch: Partial<Message>): void {
  const session = getSession(sessionId);
  if (!session) return;
  const idx = session.messages.findIndex((m) => m.id === msgId);
  if (idx !== -1) {
    session.messages[idx] = { ...session.messages[idx], ...patch };
    updateSession(sessionId, session);
  }
}
