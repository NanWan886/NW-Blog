// ============================================================
// NW Forum  简易论坛系统  (Cloudflare Worker + D1)
// 前后端一体，管理员面板，安全防护
// ============================================================

// ─── DB 保护 ───
function checkDB(env) {
  return !!(env && env.DB);
}

// ─── 初始化数据库 ───
async function initDatabase(env) {
  if (!checkDB(env)) return;
  try {
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        category_id INTEGER DEFAULT 1,
        pinned INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        thread_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL
      );
      INSERT OR IGNORE INTO categories (id, name, description) VALUES (1, '默认版块', '默认讨论版块');
    `);
  } catch (e) { console.error('DB init:', e); }
}

// ─── 安全函数 ───
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  const h = btoa(String.fromCharCode(...new Uint8Array(bits)));
  const s = btoa(String.fromCharCode(...salt));
  return s + ':' + h;
}

async function verifyPassword(password, stored) {
  const [s, h] = stored.split(':');
  const salt = new Uint8Array([...atob(s)].map(c => c.charCodeAt(0)));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits))) === h;
}

function generateToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2,'0')).join('');
}

function sanitize(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function parseCookie(cookieStr) {
  const o = {};
  if (!cookieStr) return o;
  cookieStr.split(';').forEach(c => { const p = c.trim().split('='); if (p.length >= 2) o[p[0]] = p.slice(1).join('='); });
  return o;
}

function setCookie(token) {
  const exp = new Date(Date.now() + 7*86400000).toUTCString();
  return 'nw_forum_token=' + token + '; HttpOnly; Secure; Path=/; SameSite=Lax; Expires=' + exp;
}
function clearCookie() {
  return 'nw_forum_token=; HttpOnly; Secure; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
}

async function getCurrentUser(env, request) {
  if (!checkDB(env)) return null;
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['nw_forum_token'];
  if (!token) return null;
  try {
    const row = await env.DB.prepare(
      "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime('now')"
    ).bind(token).first();
    return row || null;
  } catch (e) { return null; }
}

// ─── JSON ───
function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

// ─── API 路由 ───

// 注册
async function apiRegister(env, body) {
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  const { username, password } = body;
  if (!username || !password || username.length < 2 || username.length > 20 || password.length < 6)
    return json({ error: '用户名2-20字符，密码至少6字符' }, 400);
  if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(username))
    return json({ error: '用户名只允许字母、数字、下划线和中文' }, 400);
  try {
    const exist = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (exist) return json({ error: '用户名已存在' }, 409);
    const ph = await hashPassword(password);
    const cnt = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    const role = (cnt && cnt.c === 0) ? 'admin' : 'user';
    await env.DB.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').bind(username, ph, role).run();
    return json({ message: '注册成功', role });
  } catch (e) { return json({ error: '注册失败' }, 500); }
}

// 登录
async function apiLogin(env, body) {
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  const { username, password } = body;
  if (!username || !password) return json({ error: '请填写用户名和密码' }, 400);
  try {
    const u = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!u) return json({ error: '用户名或密码错误' }, 401);
    if (!(await verifyPassword(password, u.password_hash))) return json({ error: '用户名或密码错误' }, 401);
    const token = generateToken();
    const hdrs = new Headers({ 'Content-Type': 'application/json' });
    hdrs.append('Set-Cookie', setCookie(token));
    await env.DB.prepare(
      "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+7 days'))"
    ).bind(u.id, token).run();
    return new Response(JSON.stringify({ message: '登录成功', username: u.username, role: u.role }), { status: 200, headers: hdrs });
  } catch (e) { return json({ error: '登录失败' }, 500); }
}

// 登出
async function apiLogout(env, request) {
  if (!checkDB(env)) return json({ message: '已登出' });
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['nw_forum_token'];
  if (token) try { await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run(); } catch (e) {}
  const hdrs = new Headers({ 'Content-Type': 'application/json' });
  hdrs.append('Set-Cookie', clearCookie());
  return new Response(JSON.stringify({ message: '已登出' }), { status: 200, headers: hdrs });
}

// 当前用户
async function apiMe(env, request) {
  const u = await getCurrentUser(env, request);
  if (!u) return json({ error: '未登录' }, 401);
  return json({ user: { id: u.id, username: u.username, role: u.role } });
}

// 分类
async function apiCategories(env) {
  if (!checkDB(env)) return json([]);
  const r = await env.DB.prepare('SELECT * FROM categories ORDER BY id').all();
  return json(r.results || []);
}

// 帖子列表
async function apiThreads(env, request) {
  if (!checkDB(env)) return json({ threads: [], total: 0, page: 1, totalPages: 0 });
  const url = new URL(request.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20;
  const offset = (page - 1) * limit;
  try {
    const cnt = await env.DB.prepare('SELECT COUNT(*) as total FROM threads').first();
    const total = cnt ? cnt.total : 0;
    const rows = await env.DB.prepare(`
      SELECT t.id, t.title, t.user_id, t.pinned, t.views, t.created_at, t.updated_at,
             u.username, (SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as reply_count,
             c.name as category_name
      FROM threads t JOIN users u ON t.user_id = u.id LEFT JOIN categories c ON t.category_id = c.id
      ORDER BY t.pinned DESC, t.updated_at DESC LIMIT ? OFFSET ?
    `).bind(limit, offset).all();
    return json({ threads: rows.results || [], total, page, totalPages: Math.ceil(total / limit) });
  } catch (e) { return json({ threads: [], total: 0, page: 1, totalPages: 0 }); }
}

// 帖子详情
async function apiThreadDetail(env, id) {
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    const t = await env.DB.prepare(`
      SELECT t.*, u.username, c.name as category_name FROM threads t JOIN users u ON t.user_id = u.id LEFT JOIN categories c ON t.category_id = c.id WHERE t.id = ?
    `).bind(id).first();
    if (!t) return json({ error: '帖子不存在' }, 404);
    await env.DB.prepare('UPDATE threads SET views = views + 1 WHERE id = ?').bind(id).run();
    const posts = await env.DB.prepare(
      'SELECT p.*, u.username, u.role FROM posts p JOIN users u ON p.user_id = u.id WHERE p.thread_id = ? ORDER BY p.created_at ASC'
    ).bind(id).all();
    return json({ thread: t, posts: posts.results || [] });
  } catch (e) { return json({ error: '查询失败' }, 500); }
}

// 创建帖子
async function apiCreateThread(env, request, body) {
  const u = await getCurrentUser(env, request);
  if (!u) return json({ error: '请先登录' }, 401);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  const { title, content } = body;
  if (!title || !content) return json({ error: '标题和内容不能为空' }, 400);
  if (title.length > 100) return json({ error: '标题不能超过100字符' }, 400);
  try {
    const r = await env.DB.prepare(
      'INSERT INTO threads (title, content, user_id) VALUES (?, ?, ?)'
    ).bind(sanitize(title), sanitize(content), u.id).run();
    return json({ message: '发帖成功', id: r.meta.last_row_id }, 201);
  } catch (e) { return json({ error: '发帖失败' }, 500); }
}

// 创建回复
async function apiCreatePost(env, request, body) {
  const u = await getCurrentUser(env, request);
  if (!u) return json({ error: '请先登录' }, 401);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  const { content, thread_id } = body;
  if (!content) return json({ error: '内容不能为空' }, 400);
  try {
    const t = await env.DB.prepare('SELECT id FROM threads WHERE id = ?').bind(thread_id).first();
    if (!t) return json({ error: '帖子不存在' }, 404);
    await env.DB.prepare('INSERT INTO posts (content, user_id, thread_id) VALUES (?, ?, ?)').bind(sanitize(content), u.id, thread_id).run();
    await env.DB.prepare("UPDATE threads SET updated_at = datetime('now') WHERE id = ?").bind(thread_id).run();
    return json({ message: '回复成功' }, 201);
  } catch (e) { return json({ error: '回复失败' }, 500); }
}

// 删除帖子
async function apiDeleteThread(env, request, id) {
  const u = await getCurrentUser(env, request);
  if (!u) return json({ error: '未登录' }, 401);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    const t = await env.DB.prepare('SELECT user_id FROM threads WHERE id = ?').bind(id).first();
    if (!t) return json({ error: '帖子不存在' }, 404);
    if (u.role !== 'admin' && t.user_id !== u.id) return json({ error: '无权操作' }, 403);
    await env.DB.prepare('DELETE FROM posts WHERE thread_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM threads WHERE id = ?').bind(id).run();
    return json({ message: '删除成功' });
  } catch (e) { return json({ error: '删除失败' }, 500); }
}

// 删除回复
async function apiDeletePost(env, request, id) {
  const u = await getCurrentUser(env, request);
  if (!u) return json({ error: '未登录' }, 401);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    const p = await env.DB.prepare('SELECT user_id FROM posts WHERE id = ?').bind(id).first();
    if (!p) return json({ error: '回复不存在' }, 404);
    if (u.role !== 'admin' && p.user_id !== u.id) return json({ error: '无权操作' }, 403);
    await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
    return json({ message: '删除成功' });
  } catch (e) { return json({ error: '删除失败' }, 500); }
}

// 管理员统计
async function apiAdminStats(env, request) {
  const u = await getCurrentUser(env, request);
  if (!u || u.role !== 'admin') return json({ error: '无权访问' }, 403);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    const uc = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
    const tc = await env.DB.prepare('SELECT COUNT(*) as c FROM threads').first();
    const pc = await env.DB.prepare('SELECT COUNT(*) as c FROM posts').first();
    const ru = await env.DB.prepare('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC LIMIT 5').all();
    return json({ users: uc.c, threads: tc.c, posts: pc.c, recentUsers: ru.results || [] });
  } catch (e) { return json({ error: '查询失败' }, 500); }
}

// 管理员用户列表
async function apiAdminUsers(env, request) {
  const u = await getCurrentUser(env, request);
  if (!u || u.role !== 'admin') return json({ error: '无权访问' }, 403);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    const rows = await env.DB.prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all();
    return json(rows.results || []);
  } catch (e) { return json({ error: '查询失败' }, 500); }
}

// 管理员设角色
async function apiAdminSetRole(env, request, body) {
  const u = await getCurrentUser(env, request);
  if (!u || u.role !== 'admin') return json({ error: '无权访问' }, 403);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  const { user_id, role } = body;
  if (!['user', 'admin'].includes(role)) return json({ error: '无效角色' }, 400);
  try {
    await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, user_id).run();
    return json({ message: '角色已更新' });
  } catch (e) { return json({ error: '更新失败' }, 500); }
}

// 管理员删除用户
async function apiAdminDeleteUser(env, request, id) {
  const u = await getCurrentUser(env, request);
  if (!u || u.role !== 'admin') return json({ error: '无权访问' }, 403);
  if (parseInt(id) === u.id) return json({ error: '不能删除自己' }, 400);
  if (!checkDB(env)) return json({ error: '数据库未配置' }, 503);
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM posts WHERE user_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM threads WHERE user_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
    return json({ message: '用户已删除' });
  } catch (e) { return json({ error: '删除失败' }, 500); }
}

// ─── 前端 HTML ───

function renderFrontend(user) {
  const u = user || {};
  const userJSON = user ? JSON.stringify({ id: user.id, username: user.username, role: user.role }) : 'null';

  return '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>NW Forum 交流论坛</title>\n<style>\n'
+ '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\n'
+ ':root{--bg:#f5f7fa;--s:#fff;--s2:#f0f2f5;--t:#1a1a2e;--t2:#6b7280;--p:#6366f1;--ph:#4f46e5;--pl:#eef2ff;--d:#ef4444;--dh:#dc2626;--g:#22c55e;--b:#e5e7eb;--sh:0 1px 3px rgba(0,0,0,.08);--shl:0 8px 32px rgba(0,0,0,.1);--r:12px;--rs:8px;--tr:.3s cubic-bezier(.4,0,.2,1)}\n'
+ 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--t);line-height:1.6;min-height:100vh}\n'
+ 'a{color:var(--p);text-decoration:none;transition:color var(--tr)}a:hover{color:var(--ph)}\n'
+ '.navbar{background:var(--s);border-bottom:1px solid var(--b);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:var(--sh);backdrop-filter:blur(12px);background:rgba(255,255,255,.92)}\n'
+ '.navbar .logo{font-size:1.2rem;font-weight:700;background:linear-gradient(135deg,var(--p),#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}\n'
+ '.nav-links{display:flex;align-items:center;gap:12px}\n'
+ '.nav-links a,.nav-links button{padding:8px 16px;border-radius:var(--rs);transition:all var(--tr);font-size:.875rem;cursor:pointer;border:none;background:none;color:var(--t2);font-family:inherit}\n'
+ '.nav-links a:hover,.nav-links button:hover{background:var(--s2);color:var(--t)}\n'
+ '.nav-links .btn-p{background:var(--p);color:#fff}.nav-links .btn-p:hover{background:var(--ph);color:#fff}\n'
+ '.nav-user{display:flex;align-items:center;gap:8px;font-size:.875rem}\n'
+ '.nav-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,var(--p),#a855f7);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:.8rem}\n'
+ '.badge{background:var(--d);color:#fff;padding:2px 8px;border-radius:99px;font-size:.7rem;font-weight:600}\n'
+ '.container{max-width:960px;margin:0 auto;padding:24px 16px}\n'
+ '@keyframes pageIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}\n'
+ '.page{animation:pageIn .35s cubic-bezier(.4,0,.2,1)}\n'
+ '.card{background:var(--s);border-radius:var(--r);padding:20px;box-shadow:var(--sh);transition:all var(--tr);border:1px solid var(--b)}\n'
+ '.card:hover{box-shadow:var(--shl)}.card+.card{margin-top:12px}\n'
+ '.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border:none;border-radius:var(--rs);font-size:.875rem;font-weight:500;cursor:pointer;transition:all var(--tr);font-family:inherit;background:var(--s2);color:var(--t);white-space:nowrap}\n'
+ '.btn:hover{transform:translateY(-1px);box-shadow:var(--shl)}\n'
+ '.btn:active{transform:translateY(0)}\n'
+ '.btn-p{background:var(--p);color:#fff}.btn-p:hover{background:var(--ph)}\n'
+ '.btn-d{background:var(--d);color:#fff}.btn-d:hover{background:var(--dh)}\n'
+ '.btn-sm{padding:6px 12px;font-size:.8rem}\n'
+ '.form-group{margin-bottom:16px}\n'
+ '.form-group label{display:block;font-size:.875rem;font-weight:500;margin-bottom:6px;color:var(--t2)}\n'
+ '.form-input,.form-textarea{width:100%;padding:10px 14px;border:2px solid var(--b);border-radius:var(--rs);font-size:.9rem;transition:all var(--tr);background:var(--s);color:var(--t);font-family:inherit;outline:none}\n'
+ '.form-input:focus,.form-textarea:focus{border-color:var(--p);box-shadow:0 0 0 3px var(--pl)}\n'
+ '.form-textarea{min-height:120px;resize:vertical}\n'
+ '.auth-wrap{max-width:420px;margin:60px auto}\n'
+ '.auth-tabs{display:flex;gap:0;margin-bottom:24px;background:var(--s2);border-radius:var(--rs);overflow:hidden}\n'
+ '.auth-tabs button{flex:1;padding:12px;border:none;background:transparent;font-size:.9rem;font-weight:500;cursor:pointer;transition:all var(--tr);color:var(--t2);font-family:inherit}\n'
+ '.auth-tabs button.active{background:var(--p);color:#fff}\n'
+ '.auth-form{display:none;animation:pageIn .3s ease}.auth-form.active{display:block}\n'
+ '.thread-item{display:flex;gap:16px;padding:16px 0;border-bottom:1px solid var(--b);transition:all var(--tr);cursor:pointer}\n'
+ '.thread-item:last-child{border-bottom:none}\n'
+ '.thread-item:hover{padding-left:8px}\n'
+ '.thread-info{flex:1;min-width:0}\n'
+ '.thread-title{font-size:1.05rem;font-weight:600;margin-bottom:4px;color:var(--t)}\n'
+ '.thread-meta{font-size:.8rem;color:var(--t2);display:flex;gap:16px;flex-wrap:wrap}\n'
+ '.thread-stats{text-align:right;flex-shrink:0;font-size:.85rem;color:var(--t2)}\n'
+ '.pin-badge{display:inline-block;background:var(--pl);color:var(--p);padding:2px 8px;border-radius:99px;font-size:.7rem;font-weight:600;margin-left:8px}\n'
+ '.thread-header{margin-bottom:20px;padding-bottom:16px;border-bottom:1px solid var(--b)}\n'
+ '.thread-header h1{font-size:1.5rem;margin-bottom:8px}\n'
+ '.thread-content{font-size:.95rem;line-height:1.8;white-space:pre-wrap;word-break:break-word}\n'
+ '.post-item{padding:16px;border-left:3px solid var(--p);background:var(--s2);border-radius:0 var(--rs) var(--rs) 0;margin-bottom:12px;animation:pageIn .3s ease}\n'
+ '.post-item:nth-child(2){animation-delay:50ms}.post-item:nth-child(3){animation-delay:100ms}\n'
+ '.post-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:.85rem}\n'
+ '.post-author{font-weight:600;display:flex;align-items:center;gap:8px}\n'
+ '.post-content{white-space:pre-wrap;word-break:break-word;font-size:.9rem}\n'
+ '.pagination{display:flex;justify-content:center;gap:8px;margin-top:24px}\n'
+ '.pagination button{padding:8px 14px;border:1px solid var(--b);background:var(--s);border-radius:var(--rs);cursor:pointer;transition:all var(--tr);font-family:inherit;font-size:.85rem}\n'
+ '.pagination button:hover{background:var(--s2)}\n'
+ '.pagination button.active{background:var(--p);color:#fff;border-color:var(--p)}\n'
+ '.pagination button:disabled{opacity:.4;cursor:not-allowed}\n'
+ '.admin-bar{display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap}\n'
+ '.admin-bar button{padding:10px 20px;border:2px solid var(--b);background:var(--s);border-radius:var(--rs);cursor:pointer;font-size:.85rem;font-weight:500;transition:all var(--tr);font-family:inherit;color:var(--t2)}\n'
+ '.admin-bar button:hover{border-color:var(--p);color:var(--t)}\n'
+ '.admin-bar button.active{background:var(--p);color:#fff;border-color:var(--p)}\n'
+ '.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}\n'
+ '.stat{background:var(--s);border:1px solid var(--b);border-radius:var(--r);padding:20px;text-align:center;transition:all var(--tr)}\n'
+ '.stat:hover{transform:translateY(-2px);box-shadow:var(--shl)}\n'
+ '.stat-num{font-size:2rem;font-weight:700;color:var(--p)}\n'
+ '.stat-label{font-size:.85rem;color:var(--t2);margin-top:4px}\n'
+ '.tbl{width:100%;border-collapse:collapse;font-size:.85rem}\n'
+ '.tbl th{text-align:left;padding:12px 8px;border-bottom:2px solid var(--b);color:var(--t2);font-weight:600}\n'
+ '.tbl td{padding:10px 8px;border-bottom:1px solid var(--b)}\n'
+ '.tbl tr:hover td{background:var(--s2)}\n'
+ '.loading{text-align:center;padding:40px;color:var(--t2)}\n'
+ '.spinner{width:32px;height:32px;border:3px solid var(--b);border-top-color:var(--p);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 12px}\n'
+ '@keyframes spin{to{transform:rotate(360deg)}}\n'
+ '.toast-wrap{position:fixed;top:80px;right:20px;z-index:300;display:flex;flex-direction:column;gap:8px}\n'
+ '.toast{padding:12px 20px;border-radius:var(--rs);background:var(--s);box-shadow:var(--shl);font-size:.875rem;animation:slR .3s ease,fo .3s ease 2.7s forwards;border-left:4px solid var(--p);max-width:320px}\n'
+ '.toast.err{border-left-color:var(--d)}.toast.ok{border-left-color:var(--g)}\n'
+ '@keyframes slR{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}\n'
+ '@keyframes fo{to{opacity:0;transform:translateX(40px)}}\n'
+ '.empty{text-align:center;padding:60px 20px;color:var(--t2)}\n'
+ '.empty .icon{font-size:3rem;margin-bottom:12px}\n'
+ '@media(max-width:640px){.navbar{padding:0 12px}.container{padding:16px 12px}.auth-wrap{margin:30px auto}.thread-stats{display:none}}\n'
+ '</style>\n</head>\n<body>\n'
+ '<!-- Navbar -->\n'
+ '<nav class="navbar"><a href="/" class="logo" onclick="nv(event,\'/\')">NW Forum</a>'
+ '<div class="nav-links">'
+ '<span id="navUser" style="display:none" class="nav-user">'
+ '<span class="nav-avatar" id="navAvatar">U</span>'
+ '<span id="navUsername"></span>'
+ '<span class="badge" id="navBadge" style="display:none">管理员</span></span>'
+ '<a href="/" onclick="nv(event,\'/\')">首页</a>'
+ '<a href="/new" onclick="nv(event,\'/new\')" id="navNew" style="display:none">发帖</a>'
+ '<a href="/admin" onclick="nv(event,\'/admin\')" id="navAdmin" style="display:none">管理</a>'
+ '<a href="/login" onclick="nv(event,\'/login\')" id="navLogin">登录</a>'
+ '<button id="navLogout" style="display:none" onclick="doLogout()">登出</button>'
+ '</div></nav>\n'
+ '<div class="toast-wrap" id="toasts"></div>\n'
+ '<main class="container" id="app"></main>\n'
+ '<script>\n(function(){\n'
+ 'var CU=' + userJSON + ';\n'
+ 'var cp=1;\n'
+ 'function nv(e,p){e&&e.preventDefault();history.pushState(null,"",p);doRoute()}\n'
+ 'window.addEventListener("popstate",doRoute);\n'
+ 'function t(msg,ty){var c=document.getElementById("toasts");var d=document.createElement("div");d.className="toast "+(ty==="error"?"err":"ok");d.textContent=msg;c.appendChild(d);setTimeout(function(){d.remove()},3000)}\n'
+ 'function api(m,pth,bd){var opts={method:m,headers:{}};if(bd){opts.headers["Content-Type"]="application/json";opts.body=JSON.stringify(bd)}'
+ 'return fetch("/api"+pth,opts).then(function(r){return r.json().then(function(d){if(!r.ok&&d.error)throw new Error(d.error);return d})})}\n'
+ 'function updNav(){'
+ 'var lo=document.getElementById("navLogin");var lout=document.getElementById("navLogout");'
+ 'var nu=document.getElementById("navUser");var na=document.getElementById("navAvatar");'
+ 'var nun=document.getElementById("navUsername");var nb=document.getElementById("navBadge");'
+ 'var nn=document.getElementById("navNew");var nad=document.getElementById("navAdmin");'
+ 'if(CU){lo.style.display="none";lout.style.display="";nu.style.display="";'
+ 'na.textContent=CU.username.charAt(0).toUpperCase();nun.textContent=CU.username;'
+ 'nb.style.display=CU.role==="admin"?"":"none";nn.style.display="";nad.style.display=CU.role==="admin"?"":"none"}'
+ 'else{lo.style.display="";lout.style.display="none";nu.style.display="none";nn.style.display="none";nad.style.display="none"}}\n'
+ 'function doLogout(){api("POST","/auth/logout").then(function(){CU=null;updNav();nv(null,"/")}).catch(function(e){})}\n'
+ 'function esc(s){var d=document.createElement("div");d.textContent=s||"";return d.innerHTML}\n'
+ 'function tago(d){var dt=new Date(d+"Z");var s=Math.floor((new Date()-dt)/1000);'
+ 'if(s<60)return "刚刚";var m=Math.floor(s/60);if(m<60)return m+"分钟前";var h=Math.floor(m/60);if(h<24)return h+"小时前";'
+ 'var dy=Math.floor(h/24);if(dy<30)return dy+"天前";return (d||"").split(" ")[0]}\n'
+ 'function ld(){return \'<div class="loading"><div class="spinner"></div><p>加载中...</p></div>\'}\n'
+ 'function doRoute(){var p=window.location.pathname;if(p==="/login")pgLogin();else if(p==="/new")pgNew();else if(p==="/admin")pgAdmin();else if(p.indexOf("/thread/")===0)pgThread(p.split("/")[2]);else pgHome()}\n'
+ // ─── 首页 ───
+ 'function pgHome(){var a=document.getElementById("app");a.innerHTML=\'<div class="page"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px"><h2> 全部帖子</h2>\'+(CU?\'<button class="btn btn-p" onclick="nv(event,\'/new\')">+ 发新帖</button>\':"")+"</div>"+ld()+"</div>";'
+ 'api("GET","/threads?page="+cp).then(function(d){'
+ 'var h=\'<div class="page"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px"><h2> 全部帖子</h2>\'+(CU?\'<button class="btn btn-p" onclick="nv(event,\'/new\')">+ 发新帖</button>\':"")+"</div>";'
+ 'if(!d.threads||d.threads.length===0){h+=\'<div class="card empty"><div class="icon"></div><p>还没有帖子，来发布第一条吧</p></div>\'}'
+ 'else{d.threads.forEach(function(t){h+=\'<div class="card thread-item" onclick="nv(event,\'/thread/\'+t.id+\')\'">\';'
+ 'h+=\'<div class="thread-info">\';if(t.pinned===1)h+=\'<span class="pin-badge">置顶</span>\';'
+ 'h+=\'<div class="thread-title">\'+esc(t.title)+'</div>\';'
+ 'h+=\'<div class="thread-meta"><span> \'+esc(t.username)+'</span><span> \'+(t.category_name||"默认")+'</span><span> \'+tago(t.created_at)+'</span></div></div>\';'
+ 'h+=\'<div class="thread-stats"><div> \'+(t.reply_count||0)+'</div><div> \'+t.views+'</div></div></div>\'});'
+ 'if(d.totalPages>1){h+=\'<div class="pagination">\';'
+ 'h+=\'<button onclick="changePg(\'+(cp-1)+\')\" \'+(cp<=1?"disabled":"")+\'>上一页</button>\';'
+ 'for(var i=1;i<=d.totalPages;i++)h+=\'<button onclick="changePg(\'+i+\')\" class="\'+(i===cp?"active":"")+\'">\'+i+'</button>\';'
+ 'h+=\'<button onclick="changePg(\'+(cp+1)+\')\" \'+(cp>=d.totalPages?"disabled":"")+\'>下一页</button></div>\'}}'
+ 'h+=\'</div>\';a.innerHTML=h}).catch(function(){a.innerHTML=\'<div class="page"><h2> 全部帖子</h2><div class="card empty"><div class="icon"> </div><p>数据库未配置，请先在 Cloudflare Dashboard 绑定 D1 数据库</p></div></div>\'})}\n'
+ 'window.changePg=function(p){cp=p;pgHome()};\n'
+ // ─── 帖子详情 ───
+ 'function pgThread(id){var a=document.getElementById("app");a.innerHTML=\'<div class="page">\'+ld()+'</div>\';'
+ 'api("GET","/threads/"+id).then(function(d){var t=d.thread,ps=d.posts||[];'
+ 'var h=\'<div class="page"><a href="/" onclick="nv(event,\'/\')" style="margin-bottom:16px;display:inline-block"> 返回首页</a>\';'
+ 'h+=\'<div class="card"><div class="thread-header">\';if(t.pinned===1)h+=\'<span class="pin-badge">置顶</span>\';'
+ 'h+=\'<h1>\'+esc(t.title)+'</h1><div class="thread-meta"><span> \'+esc(t.username)+'</span><span> \'+(t.category_name||"默认")+'</span><span> \'+t.created_at+'</span><span> \'+t.views+\' 次浏览</span></div></div>\';'
+ 'h+=\'<div class="thread-content">\'+esc(t.content)+'</div>\';'
+ 'if(CU&&(CU.role==="admin"||CU.id===t.user_id))h+=\'<div style="margin-top:16px"><button class="btn btn-d btn-sm" onclick="delThr(\'+t.id+\')"> 删除</button></div>\';'
+ 'h+=\'</div><h3 style="margin:20px 0 12px"> 回复 (\'+ps.length+\')</h3>\';'
+ 'if(ps.length===0)h+=\'<p style="color:var(--t2);margin-bottom:16px">暂无回复</p>\';'
+ 'ps.forEach(function(p){h+=\'<div class="post-item"><div class="post-header"><span class="post-author">\'+esc(p.username);'
+ 'if(p.role==="admin")h+=\' <span class="badge">管理员</span>\';'
+ 'h+=\'</span><span style="font-size:.8rem;color:var(--t2)">\'+tago(p.created_at)+'</span></div>\';'
+ 'h+=\'<div class="post-content">\'+esc(p.content)+'</div>\';'
+ 'if(CU&&(CU.role==="admin"||CU.id===p.user_id))h+=\'<div style="margin-top:8px"><button class="btn btn-d btn-sm" onclick="delPost(\'+p.id+\')"> 删除</button></div>\';'
+ 'h+=\'</div>\'});'
+ 'if(CU){h+=\'<div class="card" style="margin-top:20px"><h4 style="margin-bottom:12px">发表回复</h4><textarea class="form-textarea" id="rpCont" placeholder="写下你的回复..." style="margin-bottom:12px"></textarea><button class="btn btn-p" onclick="doReply(\'+id+\')">发表回复</button></div>\'}'
+ 'h+=\'</div>\';a.innerHTML=h}).catch(function(){a.innerHTML=\'<div class="page"><p>加载失败</p></div>\'})}\n'
+ 'window.doReply=function(tid){var c=document.getElementById("rpCont").value;if(!c.trim())return t("请输入内容","error");'
+ 'api("POST","/posts",{content:c,thread_id:parseInt(tid)}).then(function(){t("回复成功");pgThread(tid)}).catch(function(e){})};\n'
+ 'window.delThr=function(id){if(!confirm("确定删除？"))return;api("DELETE","/threads/"+id).then(function(){t("已删除");nv(null,"/")}).catch(function(e){})};\n'
+ 'window.delPost=function(id){if(!confirm("确定删除？"))return;api("DELETE","/posts/"+id).then(function(){t("已删除");doRoute()}).catch(function(e){})};\n'
+ // ─── 发帖 ───
+ 'function pgNew(){if(!CU){t("请先登录","error");nv(null,"/login");return}'
+ 'var a=document.getElementById("app");a.innerHTML=\'<div class="page"><h2 style="margin-bottom:20px"> 发布新帖</h2><div class="card">'
+'<div class="form-group"><label>标题</label><input class="form-input" id="thrTitle" placeholder="帖子标题" maxlength="100"></div>'
+'<div class="form-group"><label>内容</label><textarea class="form-textarea" id="thrCont" placeholder="写下内容..." style="min-height:180px"></textarea></div>'
+'<button class="btn btn-p" onclick="doNewThread()">发布帖子</button></div></div>\'}\n'
+ 'window.doNewThread=function(){var ti=document.getElementById("thrTitle").value;var co=document.getElementById("thrCont").value;'
+ 'if(!ti.trim())return t("请输入标题","error");if(!co.trim())return t("请输入内容","error");'
+ 'api("POST","/threads",{title:ti,content:co}).then(function(){t("发帖成功");nv(null,"/")}).catch(function(e){})};\n'
+ // ─── 登录 ───
+ 'function pgLogin(){var a=document.getElementById("app");a.innerHTML=\'<div class="page auth-wrap">'
+'<h2 style="text-align:center;margin-bottom:8px"> 欢迎回来</h2><p style="text-align:center;color:var(--t2);margin-bottom:24px">登录或注册账号</p>'
+'<div class="auth-tabs"><button class="active" onclick="swATab(\'login\')">登录</button><button onclick="swATab(\'register\')">注册</button></div>'
+'<div class="auth-form active" id="loginForm"><div class="form-group"><label>用户名</label><input class="form-input" id="lgUser" placeholder="输入用户名"></div>'
+'<div class="form-group"><label>密码</label><input class="form-input" type="password" id="lgPass" placeholder="输入密码"></div>'
+'<button class="btn btn-p" style="width:100%;justify-content:center" onclick="doLogin()">登录</button></div>'
+'<div class="auth-form" id="registerForm"><div class="form-group"><label>用户名</label><input class="form-input" id="rgUser" placeholder="2-20个字符"></div>'
+'<div class="form-group"><label>密码</label><input class="form-input" type="password" id="rgPass" placeholder="至少6个字符"></div>'
+'<button class="btn btn-p" style="width:100%;justify-content:center" onclick="doRegister()">注册</button></div></div>\'}\n'
+ 'window.swATab=function(tb){var fs=document.querySelectorAll(".auth-form");var bs=document.querySelectorAll(".auth-tabs button");'
+ 'fs.forEach(function(f){f.classList.remove("active")});bs.forEach(function(b){b.classList.remove("active")});'
+ 'if(tb==="login"){document.getElementById("loginForm").classList.add("active");document.querySelector(".auth-tabs button:first-child").classList.add("active")}'
+ 'else{document.getElementById("registerForm").classList.add("active");document.querySelector(".auth-tabs button:last-child").classList.add("active")}};\n'
+ 'window.doLogin=function(){var u=document.getElementById("lgUser").value;var p=document.getElementById("lgPass").value;'
+ 'api("POST","/auth/login",{username:u,password:p}).then(function(d){CU={id:d.id||0,username:d.username,role:d.role};updNav();t("登录成功");nv(null,"/")}).catch(function(e){})};\n'
+ 'window.doRegister=function(){var u=document.getElementById("rgUser").value;var p=document.getElementById("rgPass").value;'
+ 'api("POST","/auth/register",{username:u,password:p}).then(function(){t("注册成功，请登录");swATab("login")}).catch(function(e){})};\n'
+ // ─── 管理 ───
+ 'var adTab="dashboard";\n'
+ 'function pgAdmin(){if(!CU||CU.role!=="admin"){t("无权访问","error");nv(null,"/");return}'
+ 'var a=document.getElementById("app");a.innerHTML=\'<div class="page"><h2 style="margin-bottom:8px"> 管理面板</h2><p style="color:var(--t2);margin-bottom:20px">论坛管理控制台</p>'
+'<div class="admin-bar"><button class="active" onclick="swAdTab(\'dashboard\')"> 概览</button><button onclick="swAdTab(\'users\')"> 用户</button><button onclick="swAdTab(\'threads\')"> 帖子</button></div>'
+'<div id="adContent">\'+ld()+'</div></div>\';pgAdDash()}\n'
+ 'window.swAdTab=function(tb){adTab=tb;var bs=document.querySelectorAll(".admin-bar button");bs.forEach(function(b){b.classList.remove("active")});'
+ 'bs.forEach(function(b){if((tb==="dashboard"&&b.textContent.indexOf("概览")!==-1)||(tb==="users"&&b.textContent.indexOf("用户")!==-1)||(tb==="threads"&&b.textContent.indexOf("帖子")!==-1))b.classList.add("active")});'
+ 'if(tb==="dashboard")pgAdDash();else if(tb==="users")pgAdUsers();else if(tb==="threads")pgAdThreads()};\n'
+ 'function pgAdDash(){var e=document.getElementById("adContent");e.innerHTML=ld();'
+ 'api("GET","/admin/stats").then(function(s){'
+ 'var h=\'<div class="stats"><div class="stat"><div class="stat-num">\'+s.users+'</div><div class="stat-label">用户数</div></div>'
+'<div class="stat"><div class="stat-num">\'+s.threads+'</div><div class="stat-label">帖子数</div></div>'
+'<div class="stat"><div class="stat-num">\'+s.posts+'</div><div class="stat-label">回复数</div></div></div>\';'
+'<div class="card"><h4 style="margin-bottom:12px">最近注册</h4>\';'
+ 'if(s.recentUsers&&s.recentUsers.length>0){h+=\'<table class="tbl"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>注册时间</th></tr></thead><tbody>\';'
+ 's.recentUsers.forEach(function(u){h+=\'<tr><td>\'+u.id+'</td><td>\'+esc(u.username)+'</td><td>\'+(u.role==="admin"?\'<span class="badge">管理员</span>\':"用户")+'</td><td>\'+u.created_at+'</td></tr>\'});'
+ 'h+=\'</tbody></table>\'}h+=\'</div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+ 'function pgAdUsers(){var e=document.getElementById("adContent");e.innerHTML=ld();'
+ 'api("GET","/admin/users").then(function(us){'
+ 'var h=\'<div class="card"><h4 style="margin-bottom:12px"> 用户管理</h4><table class="tbl"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>注册时间</th><th>操作</th></tr></thead><tbody>\';'
+ 'us.forEach(function(u){h+=\'<tr><td>\'+u.id+'</td><td>\'+esc(u.username)+'</td><td>\'+(u.role==="admin"?\'<span class="badge">管理员</span>\':"用户")+'</td><td>\'+u.created_at+'</td><td>\';'
+ 'if(u.id!==CU.id){if(u.role!=="admin")h+=\'<button class="btn btn-sm" onclick="adSetRole(\'+u.id+\',\\\'admin\\\')\'">设管理员</button> \';'
+ 'else h+=\'<button class="btn btn-sm" onclick="adSetRole(\'+u.id+\',\\\'user\\\')\'">设为用户</button> \';'
+ 'h+=\'<button class="btn btn-d btn-sm" onclick="adDelUser(\'+u.id+\')">删除</button>\'}else{h+=\'<span style="color:var(--t2)">当前用户</span>\'}h+=\'</td></tr>\'});'
+ 'h+=\'</tbody></table></div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+ 'window.adSetRole=function(uid,role){api("POST","/admin/set-role",{user_id:uid,role:role}).then(function(){t("角色已更新");pgAdUsers()}).catch(function(e){})};\n'
+ 'window.adDelUser=function(uid){if(!confirm("确定删除？"))return;api("DELETE","/admin/users/"+uid).then(function(){t("用户已删除");pgAdUsers()}).catch(function(e){})};\n'
+ 'function pgAdThreads(){var e=document.getElementById("adContent");e.innerHTML=ld();'
+ 'api("GET","/threads?page=1").then(function(d){'
+ 'var h=\'<div class="card"><h4 style="margin-bottom:12px"> 帖子管理</h4><table class="tbl"><thead><tr><th>ID</th><th>标题</th><th>作者</th><th>回复</th><th>时间</th><th>操作</th></tr></thead><tbody>\';'
+ 'd.threads.forEach(function(t){h+=\'<tr><td>\'+t.id+'</td><td>\'+esc(t.title).substring(0,30)+'</td><td>\'+esc(t.username)+'</td><td>\'+(t.reply_count||0)+'</td><td>\'+tago(t.created_at)+'</td><td>\';'
+ 'h+=\'<button class="btn btn-d btn-sm" onclick="adDelThr(\'+t.id+\')">删除</button></td></tr>\'});'
+ 'h+=\'</tbody></table></div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+ 'window.adDelThr=function(id){if(!confirm("确定删除？"))return;api("DELETE","/threads/"+id).then(function(){t("已删除");pgAdThreads()}).catch(function(e){})};\n'
+ // ─── 初始化 ───
+ 'updNav();doRoute();})();\n</script>\n</body>\n</html>';
+}

// ─── 主入口 ───
export default {
  async fetch(request, env, ctx) {
    // 初始化数据库（无 D1 时静默跳过）
    try { await initDatabase(env); } catch (e) {}

    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path.startsWith('/api/')) {
      const p = path.replace('/api', '');
      const m = request.method;
      let body = {};
      if (['POST','PUT','DELETE'].includes(m)) {
        try { body = await request.json(); } catch (e) {}
      }

      // 需要鉴权的写操作先验 DB
      // Auth
      if (p === '/auth/register' && m === 'POST') return apiRegister(env, body);
      if (p === '/auth/login' && m === 'POST') return apiLogin(env, body);
      if (p === '/auth/logout' && m === 'POST') return apiLogout(env, request);
      if (p === '/me' && m === 'GET') return apiMe(env, request);
      // Categories
      if (p === '/categories' && m === 'GET') return apiCategories(env);
      // Threads
      if (p === '/threads' && m === 'GET') return apiThreads(env, request);
      if (p.match(/^\/threads\/\d+$/) && m === 'GET') { const id = p.split('/')[2]; return apiThreadDetail(env, id); }
      if (p === '/threads' && m === 'POST') return apiCreateThread(env, request, body);
      if (p.match(/^\/threads\/\d+$/) && m === 'DELETE') { const id = p.split('/')[2]; return apiDeleteThread(env, request, id); }
      // Posts
      if (p === '/posts' && m === 'POST') return apiCreatePost(env, request, body);
      if (p.match(/^\/posts\/\d+$/) && m === 'DELETE') { const id = p.split('/')[2]; return apiDeletePost(env, request, id); }
      // Admin
      if (p === '/admin/stats' && m === 'GET') return apiAdminStats(env, request);
      if (p === '/admin/users' && m === 'GET') return apiAdminUsers(env, request);
      if (p === '/admin/set-role' && m === 'POST') return apiAdminSetRole(env, request, body);
      if (p.match(/^\/admin\/users\/\d+$/) && m === 'DELETE') { const id = p.split('/')[3]; return apiAdminDeleteUser(env, request, id); }

      return json({ error: 'Not Found' }, 404);
    }

    // 前端页面
    try {
      const user = await getCurrentUser(env, request);
      const html = renderFrontend(user);
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    } catch (e) {
      // 紧急降级：纯 HTML 无 JS
      return new Response('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>NW Forum</title></head><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f7fa;color:#6b7280"><p>论坛正在加载，请稍后刷新。如持续出现，请检查 Cloudflare Dashboard 中的 D1 绑定。</p></body></html>', {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
  }
};
