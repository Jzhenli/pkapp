/* /api 客户端（lan 门 login 模式，NETWORK_AUTH_DESIGN §7/§8）：会话 = HttpOnly Cookie。
 *
 * 页面只在已登录时被服务（未登录一律 302 /login），故 401 只出现在会话过期等
 * 边缘态——整页跳回登录页即可；门在未登录时对 /api/* 回 401 JSON、页面 302。
 */
export async function api(path) {
  const r = await fetch(path)
  if (r.status === 401) {
    location.replace('/login')
    throw new Error('会话已过期，请重新登录')
  }
  if (!r.ok) throw new Error(`${path} → HTTP ${r.status}`)
  return r.json()
}
