import type { TargetRecord } from './types';

export const TOKEN_STORAGE_KEY = 'rc_api_token';

/**
 * 获取当前存储的 API Token
 */
export function getApiToken(): string {
  try {
    return (localStorage.getItem(TOKEN_STORAGE_KEY) || '').trim();
  } catch {
    return '';
  }
}

/**
 * 设置或移除 API Token，同时触发全局 storage 事件以便多组件响应
 */
export function setApiToken(token: string) {
  try {
    const trimmed = token.trim();
    if (trimmed) {
      localStorage.setItem(TOKEN_STORAGE_KEY, trimmed);
    } else {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
    // 派发自定义事件便于同页面不同组件即时同步
    window.dispatchEvent(new Event('rc_token_changed'));
  } catch {
    // 忽略 localStorage 异常
  }
}

/**
 * 全局统一的 API Fetch 封装：
 * 1. 自动注入 Authorization: Bearer <token> 请求头
 * 2. 如果 URL 是相对路径且包含了 query，也会自动兜底
 */
export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const token = getApiToken();
  const headers = new Headers(init.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  return fetch(input, {
    ...init,
    headers,
  });
}

/**
 * 在线复检单个目标，并返回服务端持久化后的最新资产记录。
 */
export async function recheckTarget(domain: string, ip: string): Promise<TargetRecord> {
  const res = await apiFetch('/api/targets/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, ip }),
  });

  const data = await res.json();
  if (!res.ok || data.code !== 200 || !data.data) {
    throw new Error(data.error || '目标复检失败');
  }

  return data.data as TargetRecord;
}

/** 设置或取消目标收藏。收藏目标会在服务端结果中优先展示。 */
export async function setTargetStarred(domain: string, starred: boolean): Promise<boolean> {
  const res = await apiFetch(`/api/targets/${encodeURIComponent(domain)}/star`, {
    method: starred ? 'POST' : 'DELETE',
  });
  const data = await res.json();
  if (!res.ok || data.code !== 200) {
    throw new Error(data.error || '更新收藏状态失败');
  }
  return Boolean(data.is_starred);
}

/** 设置或取消目标差评。差评目标在服务端结果中排到最后。 */
export async function setTargetDisliked(domain: string, disliked: boolean): Promise<boolean> {
  const res = await apiFetch(`/api/targets/${encodeURIComponent(domain)}/dislike`, {
    method: disliked ? 'POST' : 'DELETE',
  });
  const data = await res.json();
  if (!res.ok || data.code !== 200) {
    throw new Error(data.error || '更新差评状态失败');
  }
  return Boolean(data.is_disliked);
}
