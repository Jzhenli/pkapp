/* /api 客户端（lan 门 login 模式，NETWORK_AUTH_DESIGN §7/§8）：会话 = HttpOnly Cookie。
 *
 * 页面只在已登录时被服务（未登录一律 302 /login），故 401 只出现在会话过期等
 * 边缘态——整页跳回登录页即可；门在未登录时对 /api/* 回 401 JSON、页面 302。
 */
export async function api(path, { method = 'GET', body } = {}) {
  const r = await fetch(path, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (r.status === 401) {
    location.replace('/login')
    throw new Error('会话已过期，请重新登录')
  }
  if (!r.ok) {
    const j = await r.json().catch(() => null)
    // FastAPI 422 → detail 数组；门 403 → {error, required}；应用 HTTPException → detail 字符串
    const d = j && (j.detail ?? j.error)
    throw new Error(d ? (typeof d === 'string' ? d : JSON.stringify(d)) : `${path} → HTTP ${r.status}`)
  }
  return r.status === 204 ? null : r.json()
}

/* 权限判断：门侧约定 "*" = 全权限；viewer 等只读角色据此隐藏写操作按钮。 */
export function can(me, perm) {
  if (!me) return false
  const perms = me.perms || []
  return perms.includes('*') || perms.includes(perm)
}
