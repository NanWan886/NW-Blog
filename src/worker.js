// ============================================================
// NW Forum — 简易论坛系统 (Cloudflare Worker + D1)
// 前后端一体，含管理员面板，安全防护
// ============================================================

// ---------- 初始化数据库 ----------
async function initDatabase(env) {
  if (!env.DB) return;
  try {
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        avatar TEXT DEFAULT '',
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
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (category_id) REFERENCES categories(id)
      );
      CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        thread_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (thread_id) REFERENCES threads(id)
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      -- 插入默认分类
      INSERT OR IGNORE INTO categories (id, name, description) VALUES (1, '默认版块', '默认讨论版块');
    `);
  } catch (e) { console.error('DB init error:', e); }
}

// ---------- 安全帮助函数 ----------

// 密码哈希 (PBKDF2)
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  const saltB64 = btoa(String.fromCharCode(...salt));
  return `${saltB64}:${hash}`;
}

async function verifyPassword(password, stored) {
  const [saltB64, hash] = stored.split(':');
  const salt = new Uint8Array([...atob(saltB64)].map(c => c.charCodeAt(0)));
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  const newHash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return newHash === hash;
}

// 生成 Session Token
function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// HTML 消毒
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 获取当前登录用户
async function getCurrentUser(env, request) {
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['nw_forum_token'];
  if (!token) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.username, u.role, u.avatar FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime(\'now\')'
  ).bind(token).first();
  return row || null;
}

// 解析 Cookie
function parseCookie(cookie) {
  const obj = {};
  cookie.split(';').forEach(c => {
    const parts = c.trim().split('=');
    if (parts.length >= 2) obj[parts[0]] = parts.slice(1).join('=');
  });
  return obj;
}

// 设置 Cookie
function setCookie(token) {
  const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
  return `nw_forum_token=${token}; HttpOnly; Secure; Path=/; SameSite=Lax; Expires=${expires}`;
}

// 清除 Cookie
function clearCookie() {
  return 'nw_forum_token=; HttpOnly; Secure; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
}

// ---------- 路由处理 ----------

// API: 注册
async function handleRegister(env, body) {
  const { username, password } = body;
  if (!username || !password || username.length < 2 || username.length > 20 || password.length < 6) {
    return json({ error: '用户名2-20字符，密码至少6字符' }, 400);
  }
  if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(username)) {
    return json({ error: '用户名只允许字母、数字、下划线和中文' }, 400);
  }
  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return json({ error: '用户名已存在' }, 409);

  const password_hash = await hashPassword(password);
  // 第一个注册用户为管理员
  const count = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
  const role = count.c === 0 ? 'admin' : 'user';
  await env.DB.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').bind(username, password_hash, role).run();
  return json({ message: '注册成功', role });
}

// API: 登录
async function handleLogin(env, body) {
  const { username, password } = body;
  if (!username || !password) return json({ error: '请填写用户名和密码' }, 400);
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user) return json({ error: '用户名或密码错误' }, 401);
  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) return json({ error: '用户名或密码错误' }, 401);

  const token = generateToken();
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', setCookie(token));
  await env.DB.prepare(
    'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime(\'now\', \'+7 days\'))'
  ).bind(user.id, token).run();
  return new Response(JSON.stringify({ message: '登录成功', username: user.username, role: user.role }), { status: 200, headers });
}

// API: 登出
async function handleLogout(env, request) {
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie['nw_forum_token'];
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', clearCookie());
  return new Response(JSON.stringify({ message: '已登出' }), { status: 200, headers });
}

// API: 获取当前用户
async function handleMe(env, request) {
  const user = await getCurrentUser(env, request);
  if (!user) return json({ error: '未登录' }, 401);
  return json({ user: { id: user.id, username: user.username, role: user.role, avatar: user.avatar } });
}

// API: 获取分类列表
async function handleCategories(env) {
  const cats = await env.DB.prepare('SELECT * FROM categories ORDER BY id').all();
  return json(cats.results || []);
}

// API: 获取帖子列表
async function handleThreads(env, request) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get('page')) || 1;
  const category = url.searchParams.get('category') || '';
  const limit = 20;
  const offset = (page - 1) * limit;

  let where = '';
  let params = [];
  if (category) {
    where = 'WHERE t.category_id = ?';
    params.push(parseInt(category));
  }

  const countSql = `SELECT COUNT(*) as total FROM threads t ${where}`;
  const countResult = await env.DB.prepare(countSql).bind(...params).first();
  const total = countResult ? countResult.total : 0;

  const sql = `
    SELECT t.id, t.title, t.content, t.user_id, t.category_id, t.pinned, t.views, t.created_at, t.updated_at,
           u.username, u.avatar,
           (SELECT COUNT(*) FROM posts WHERE thread_id = t.id) as reply_count,
           c.name as category_name
    FROM threads t
    JOIN users u ON t.user_id = u.id
    LEFT JOIN categories c ON t.category_id = c.id
    ${where}
    ORDER BY t.pinned DESC, t.updated_at DESC
    LIMIT ? OFFSET ?
  `;
  const threads = await env.DB.prepare(sql).bind(...params, limit, offset).all();
  return json({ threads: threads.results || [], total, page, totalPages: Math.ceil(total / limit) });
}

// API: 获取帖子详情
async function handleThreadDetail(env, id) {
  const thread = await env.DB.prepare(`
    SELECT t.*, u.username, u.avatar, c.name as category_name
    FROM threads t
    JOIN users u ON t.user_id = u.id
    LEFT JOIN categories c ON t.category_id = c.id
    WHERE t.id = ?
  `).bind(id).first();
  if (!thread) return json({ error: '帖子不存在' }, 404);

  // 增加浏览量
  await env.DB.prepare('UPDATE threads SET views = views + 1 WHERE id = ?').bind(id).run();

  const posts = await env.DB.prepare(`
    SELECT p.*, u.username, u.avatar, u.role
    FROM posts p
    JOIN users u ON p.user_id = u.id
    WHERE p.thread_id = ?
    ORDER BY p.created_at ASC
  `).bind(id).all();

  return json({ thread, posts: posts.results || [] });
}

// API: 创建帖子
async function handleCreateThread(env, request, body) {
  const user = await getCurrentUser(env, request);
  if (!user) return json({ error: '请先登录' }, 401);

  const { title, content, category_id } = body;
  if (!title || !content) return json({ error: '标题和内容不能为空' }, 400);
  if (title.length > 100) return json({ error: '标题不能超过100字符' }, 400);

  const result = await env.DB.prepare(
    'INSERT INTO threads (title, content, user_id, category_id) VALUES (?, ?, ?, ?)'
  ).bind(sanitize(title), sanitize(content), user.id, category_id || 1).run();

  return json({ message: '发帖成功', id: result.meta.last_row_id }, 201);
}

// API: 回复帖子
async function handleCreatePost(env, request, body) {
  const user = await getCurrentUser(env, request);
  if (!user) return json({ error: '请先登录' }, 401);

  const { content, thread_id } = body;
  if (!content) return json({ error: '内容不能为空' }, 400);

  // 检查帖子是否存在
  const thread = await env.DB.prepare('SELECT id FROM threads WHERE id = ?').bind(thread_id).first();
  if (!thread) return json({ error: '帖子不存在' }, 404);

  await env.DB.prepare(
    'INSERT INTO posts (content, user_id, thread_id) VALUES (?, ?, ?)'
  ).bind(sanitize(content), user.id, thread_id).run();

  // 更新帖子最后回复时间
  await env.DB.prepare('UPDATE threads SET updated_at = datetime(\'now\') WHERE id = ?').bind(thread_id).run();

  return json({ message: '回复成功' }, 201);
}

// API: 删除帖子 (管理员或本人)
async function handleDeleteThread(env, request, id) {
  const user = await getCurrentUser(env, request);
  if (!user) return json({ error: '未登录' }, 401);

  const thread = await env.DB.prepare('SELECT * FROM threads WHERE id = ?').bind(id).first();
  if (!thread) return json({ error: '帖子不存在' }, 404);
  if (user.role !== 'admin' && thread.user_id !== user.id) return json({ error: '无权操作' }, 403);

  await env.DB.prepare('DELETE FROM posts WHERE thread_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM threads WHERE id = ?').bind(id).run();
  return json({ message: '删除成功' });
}

// API: 删除回复 (管理员或本人)
async function handleDeletePost(env, request, id) {
  const user = await getCurrentUser(env, request);
  if (!user) return json({ error: '未登录' }, 401);

  const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?').bind(id).first();
  if (!post) return json({ error: '回复不存在' }, 404);
  if (user.role !== 'admin' && post.user_id !== user.id) return json({ error: '无权操作' }, 403);

  await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
  return json({ message: '删除成功' });
}

// API: 管理员 — 获取用户列表
async function handleAdminUsers(env, request) {
  const user = await getCurrentUser(env, request);
  if (!user || user.role !== 'admin') return json({ error: '无权访问' }, 403);

  const users = await env.DB.prepare(
    'SELECT id, username, role, avatar, created_at FROM users ORDER BY id'
  ).all();
  return json(users.results || []);
}

// API: 管理员 — 更改用户角色
async function handleAdminSetRole(env, request, body) {
  const user = await getCurrentUser(env, request);
  if (!user || user.role !== 'admin') return json({ error: '无权访问' }, 403);

  const { user_id, role } = body;
  if (!['user', 'admin'].includes(role)) return json({ error: '无效角色' }, 400);
  await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?').bind(role, user_id).run();
  return json({ message: '角色已更新' });
}

// API: 管理员 — 删除用户 (不可删自己)
async function handleAdminDeleteUser(env, request, id) {
  const user = await getCurrentUser(env, request);
  if (!user || user.role !== 'admin') return json({ error: '无权访问' }, 403);
  if (parseInt(id) === user.id) return json({ error: '不能删除自己' }, 400);

  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM posts WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('UPDATE threads SET user_id = 0 WHERE user_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return json({ message: '用户已删除' });
}

// API: 管理员 — 统计数据
async function handleAdminStats(env, request) {
  const user = await getCurrentUser(env, request);
  if (!user || user.role !== 'admin') return json({ error: '无权访问' }, 403);

  const userCount = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
  const threadCount = await env.DB.prepare('SELECT COUNT(*) as c FROM threads').first();
  const postCount = await env.DB.prepare('SELECT COUNT(*) as c FROM posts').first();
  const recentUsers = await env.DB.prepare(
    'SELECT id, username, role, created_at FROM users ORDER BY created_at DESC LIMIT 5'
  ).all();
  return json({
    users: userCount.c,
    threads: threadCount.c,
    posts: postCount.c,
    recentUsers: recentUsers.results || []
  });
}

// 统一 JSON 响应
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

// ---------- 前端页面 ----------

function renderFrontend(user, path) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NW Forum · 交流论坛</title>
  <style>
    /* ===== Reset & Variables ===== */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #f5f7fa;
      --surface: #ffffff;
      --surface2: #f0f2f5;
      --text: #1a1a2e;
      --text2: #6b7280;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --primary-light: #eef2ff;
      --danger: #ef4444;
      --danger-hover: #dc2626;
      --success: #22c55e;
      --border: #e5e7eb;
      --shadow: 0 1px 3px rgba(0,0,0,0.08);
      --shadow-lg: 0 8px 32px rgba(0,0,0,0.1);
      --radius: 12px;
      --radius-sm: 8px;
      --transition: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }
    a { color: var(--primary); text-decoration: none; transition: color var(--transition); }
    a:hover { color: var(--primary-hover); }

    /* ===== Navbar ===== */
    .navbar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
      background: rgba(255,255,255,0.92);
    }
    .navbar .logo {
      font-size: 1.2rem;
      font-weight: 700;
      background: linear-gradient(135deg, var(--primary), #a855f7);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .navbar .nav-links { display: flex; align-items: center; gap: 12px; }
    .navbar .nav-links a, .navbar .nav-links button {
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      transition: all var(--transition);
      font-size: 0.875rem;
      cursor: pointer;
      border: none;
      background: none;
      color: var(--text2);
      font-family: inherit;
    }
    .navbar .nav-links a:hover, .navbar .nav-links button:hover {
      background: var(--surface2);
      color: var(--text);
    }
    .navbar .nav-links .btn-primary {
      background: var(--primary);
      color: #fff;
    }
    .navbar .nav-links .btn-primary:hover {
      background: var(--primary-hover);
      color: #fff;
    }
    .nav-user {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.875rem;
    }
    .nav-user .avatar {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--primary), #a855f7);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      font-size: 0.8rem;
    }
    .badge-admin {
      background: var(--danger);
      color: #fff;
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 0.7rem;
      font-weight: 600;
    }

    /* ===== Container ===== */
    .container {
      max-width: 960px;
      margin: 0 auto;
      padding: 24px 16px;
    }

    /* ===== Page Transitions ===== */
    .page {
      animation: pageIn 0.35s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes pageIn {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* ===== Card ===== */
    .card {
      background: var(--surface);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: var(--shadow);
      transition: all var(--transition);
      border: 1px solid var(--border);
    }
    .card:hover { box-shadow: var(--shadow-lg); }
    .card + .card { margin-top: 12px; }

    /* ===== Button ===== */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 10px 20px;
      border: none;
      border-radius: var(--radius-sm);
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: all var(--transition);
      font-family: inherit;
      background: var(--surface2);
      color: var(--text);
    }
    .btn:hover { transform: translateY(-1px); box-shadow: var(--shadow-lg); }
    .btn:active { transform: translateY(0); }
    .btn-primary { background: var(--primary); color: #fff; }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-danger { background: var(--danger); color: #fff; }
    .btn-danger:hover { background: var(--danger-hover); }
    .btn-sm { padding: 6px 12px; font-size: 0.8rem; }

    /* ===== Form ===== */
    .form-group { margin-bottom: 16px; }
    .form-group label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      margin-bottom: 6px;
      color: var(--text2);
    }
    .form-input, .form-textarea, .form-select {
      width: 100%;
      padding: 10px 14px;
      border: 2px solid var(--border);
      border-radius: var(--radius-sm);
      font-size: 0.9rem;
      transition: all var(--transition);
      background: var(--surface);
      color: var(--text);
      font-family: inherit;
      outline: none;
    }
    .form-input:focus, .form-textarea:focus, .form-select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px var(--primary-light);
    }
    .form-textarea { min-height: 120px; resize: vertical; }

    /* ===== Auth ===== */
    .auth-container {
      max-width: 420px;
      margin: 60px auto;
    }
    .auth-tabs {
      display: flex;
      gap: 0;
      margin-bottom: 24px;
      background: var(--surface2);
      border-radius: var(--radius-sm);
      overflow: hidden;
    }
    .auth-tabs button {
      flex: 1;
      padding: 12px;
      border: none;
      background: transparent;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all var(--transition);
      color: var(--text2);
      font-family: inherit;
    }
    .auth-tabs button.active {
      background: var(--primary);
      color: #fff;
    }
    .auth-form { display: none; animation: pageIn 0.3s ease; }
    .auth-form.active { display: block; }
    .auth-error {
      background: #fef2f2;
      color: var(--danger);
      padding: 10px 14px;
      border-radius: var(--radius-sm);
      font-size: 0.85rem;
      margin-bottom: 16px;
      display: none;
    }

    /* ===== Thread List ===== */
    .thread-item {
      display: flex;
      gap: 16px;
      padding: 16px 0;
      border-bottom: 1px solid var(--border);
      transition: all var(--transition);
      cursor: pointer;
    }
    .thread-item:last-child { border-bottom: none; }
    .thread-item:hover { padding-left: 8px; }
    .thread-info { flex: 1; min-width: 0; }
    .thread-title {
      font-size: 1.05rem;
      font-weight: 600;
      margin-bottom: 4px;
      color: var(--text);
    }
    .thread-meta {
      font-size: 0.8rem;
      color: var(--text2);
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }
    .thread-meta span { display: inline-flex; align-items: center; gap: 4px; }
    .thread-stats {
      text-align: right;
      flex-shrink: 0;
      font-size: 0.85rem;
      color: var(--text2);
    }
    .pinned-badge {
      display: inline-block;
      background: var(--primary-light);
      color: var(--primary);
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 0.7rem;
      font-weight: 600;
      margin-left: 8px;
    }

    /* ===== Thread Detail ===== */
    .thread-header {
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .thread-header h1 { font-size: 1.5rem; margin-bottom: 8px; }
    .thread-content {
      font-size: 0.95rem;
      line-height: 1.8;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .post-item {
      padding: 16px;
      border-left: 3px solid var(--primary);
      background: var(--surface2);
      border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
      margin-bottom: 12px;
      animation: pageIn 0.3s ease;
    }
    .post-item:nth-child(2) { animation-delay: 0.05s; }
    .post-item:nth-child(3) { animation-delay: 0.1s; }
    .post-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      font-size: 0.85rem;
    }
    .post-author { font-weight: 600; display: flex; align-items: center; gap: 8px; }
    .post-content { white-space: pre-wrap; word-break: break-word; font-size: 0.9rem; }

    /* ===== Pagination ===== */
    .pagination {
      display: flex;
      justify-content: center;
      gap: 8px;
      margin-top: 24px;
    }
    .pagination button {
      padding: 8px 14px;
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: var(--radius-sm);
      cursor: pointer;
      transition: all var(--transition);
      font-family: inherit;
      font-size: 0.85rem;
    }
    .pagination button:hover { background: var(--surface2); }
    .pagination button.active {
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
    }
    .pagination button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    /* ===== Admin ===== */
    .admin-sidebar {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    .admin-sidebar button {
      padding: 10px 20px;
      border: 2px solid var(--border);
      background: var(--surface);
      border-radius: var(--radius-sm);
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      transition: all var(--transition);
      font-family: inherit;
      color: var(--text2);
    }
    .admin-sidebar button:hover { border-color: var(--primary); color: var(--text); }
    .admin-sidebar button.active {
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
    }
    .admin-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      text-align: center;
      transition: all var(--transition);
    }
    .stat-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-lg); }
    .stat-number { font-size: 2rem; font-weight: 700; color: var(--primary); }
    .stat-label { font-size: 0.85rem; color: var(--text2); margin-top: 4px; }
    .admin-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    .admin-table th {
      text-align: left;
      padding: 12px 8px;
      border-bottom: 2px solid var(--border);
      color: var(--text2);
      font-weight: 600;
    }
    .admin-table td {
      padding: 10px 8px;
      border-bottom: 1px solid var(--border);
    }
    .admin-table tr:hover td { background: var(--surface2); }

    /* ===== Loading ===== */
    .loading {
      text-align: center;
      padding: 40px;
      color: var(--text2);
    }
    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid var(--border);
      border-top-color: var(--primary);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 12px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ===== Modal ===== */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.4);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 200;
      animation: fadeIn 0.2s ease;
    }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    .modal {
      background: var(--surface);
      border-radius: var(--radius);
      padding: 24px;
      max-width: 480px;
      width: 90%;
      animation: modalIn 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalIn {
      from { opacity: 0; transform: scale(0.95) translateY(10px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }
    .modal h2 { margin-bottom: 16px; }
    .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }

    /* ===== Responsive ===== */
    @media (max-width: 640px) {
      .navbar { padding: 0 12px; }
      .container { padding: 16px 12px; }
      .auth-container { margin: 30px auto; }
      .thread-stats { display: none; }
    }

    /* ===== Skeleton ===== */
    .skeleton {
      background: linear-gradient(90deg, var(--surface2) 25%, var(--border) 50%, var(--surface2) 75%);
      background-size: 200% 100%;
      animation: shimmer 1.5s infinite;
      border-radius: var(--radius-sm);
    }
    @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

    /* ===== Toast ===== */
    .toast-container {
      position: fixed;
      top: 80px;
      right: 20px;
      z-index: 300;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .toast {
      padding: 12px 20px;
      border-radius: var(--radius-sm);
      background: var(--surface);
      box-shadow: var(--shadow-lg);
      font-size: 0.875rem;
      animation: slideInRight 0.3s ease, fadeOut 0.3s ease 2.7s forwards;
      border-left: 4px solid var(--primary);
    }
    .toast.error { border-left-color: var(--danger); }
    .toast.success { border-left-color: var(--success); }
    @keyframes slideInRight { from { opacity: 0; transform: translateX(40px); } to { opacity: 1; transform: translateX(0); } }
    @keyframes fadeOut { to { opacity: 0; transform: translateX(40px); } }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: var(--text2);
    }
    .empty-state .icon { font-size: 3rem; margin-bottom: 12px; }
  </style>
</head>
<body>
  <!-- Navbar -->
  <nav class="navbar">
    <a href="/" class="logo" onclick="navigate(event, '/')">NW Forum</a>
    <div class="nav-links">
      <span id="navUser" style="display:none" class="nav-user">
        <span class="avatar" id="navAvatar">U</span>
        <span id="navUsername"></span>
        <span class="badge-admin" id="navBadge" style="display:none">管理员</span>
      </span>
      <a href="/" onclick="navigate(event, '/')">首页</a>
      <a href="/new" onclick="navigate(event, '/new')" id="navNewThread" style="display:none">发帖</a>
      <a href="/admin" onclick="navigate(event, '/admin')" id="navAdmin" style="display:none">管理</a>
      <a href="/login" onclick="navigate(event, '/login')" id="navLogin">登录</a>
      <button id="navLogout" style="display:none" onclick="handleLogout()">登出</button>
    </div>
  </nav>

  <!-- Toast Container -->
  <div class="toast-container" id="toastContainer"></div>

  <!-- Main Content -->
  <main class="container" id="app"></main>

  <script>
    // ===== State =====
    let currentUser = ${user ? JSON.stringify({ id: user.id, username: user.username, role: user.role }) : 'null'};
    let currentPage = 1;

    // ===== Navigation =====
    function navigate(e, path) {
      if (e) e.preventDefault();
      history.pushState(null, '', path);
      renderRoute();
    }

    window.addEventListener('popstate', renderRoute);

    // ===== Toast =====
    function toast(msg, type = 'success') {
      const c = document.getElementById('toastContainer');
      const t = document.createElement('div');
      t.className = 'toast ' + type;
      t.textContent = msg;
      c.appendChild(t);
      setTimeout(() => t.remove(), 3000);
    }

    // ===== API Helper =====
    async function api(method, path, body) {
      try {
        const opts = { method, headers: {} };
        if (body) {
          opts.headers['Content-Type'] = 'application/json';
          opts.body = JSON.stringify(body);
        }
        const res = await fetch('/api' + path, opts);
        const data = await res.json();
        if (!res.ok && data.error) throw new Error(data.error);
        return data;
      } catch (e) {
        toast(e.message, 'error');
        throw e;
      }
    }

    // ===== Update Navbar =====
    function updateNav() {
      const loginBtn = document.getElementById('navLogin');
      const logoutBtn = document.getElementById('navLogout');
      const navUser = document.getElementById('navUser');
      const navAvatar = document.getElementById('navAvatar');
      const navUsername = document.getElementById('navUsername');
      const navBadge = document.getElementById('navBadge');
      const navNewThread = document.getElementById('navNewThread');
      const navAdmin = document.getElementById('navAdmin');

      if (currentUser) {
        loginBtn.style.display = 'none';
        logoutBtn.style.display = '';
        navUser.style.display = '';
        navAvatar.textContent = currentUser.username.charAt(0).toUpperCase();
        navUsername.textContent = currentUser.username;
        navBadge.style.display = currentUser.role === 'admin' ? '' : 'none';
        navNewThread.style.display = '';
        navAdmin.style.display = currentUser.role === 'admin' ? '' : 'none';
      } else {
        loginBtn.style.display = '';
        logoutBtn.style.display = 'none';
        navUser.style.display = 'none';
        navNewThread.style.display = 'none';
        navAdmin.style.display = 'none';
      }
    }

    // ===== Logout =====
    async function handleLogout() {
      await api('POST', '/auth/logout');
      currentUser = null;
      updateNav();
      navigate(null, '/');
    }

    // ===== Render Helpers =====
    function showLoading() {
      return '<div class="loading"><div class="spinner"></div><p>加载中...</p></div>';
    }

    function escape(str) {
      const div = document.createElement('div');
      div.textContent = str || '';
      return div.innerHTML;
    }

    function timeAgo(dateStr) {
      const d = new Date(dateStr + 'Z');
      const now = new Date();
      const sec = Math.floor((now - d) / 1000);
      if (sec < 60) return '刚刚';
      const min = Math.floor(sec / 60);
      if (min < 60) return min + '分钟前';
      const hr = Math.floor(min / 60);
      if (hr < 24) return hr + '小时前';
      const day = Math.floor(hr / 24);
      if (day < 30) return day + '天前';
      return dateStr.split(' ')[0];
    }

    // ===== Routes =====
    async function renderRoute() {
      const path = window.location.pathname;
      const app = document.getElementById('app');

      if (path === '/login') renderLogin();
      else if (path === '/new') renderNewThread();
      else if (path === '/admin') renderAdmin();
      else if (path.startsWith('/thread/')) renderThread(path.split('/')[2]);
      else renderHome();
    }

    // ===== Home =====
    async function renderHome() {
      const app = document.getElementById('app');
      app.innerHTML = '<div class="page"><h2 style="margin-bottom:20px">📋 全部帖子</h2>' + showLoading() + '</div>';
      try {
        const data = await api('GET', '/threads?page=' + currentPage);
        let html = '<div class="page">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px">';
        html += '<h2>📋 全部帖子</h2>';
        if (currentUser) html += '<button class="btn btn-primary" onclick="navigate(event,\'/new\')">+ 发新帖</button>';
        html += '</div>';

        if (!data.threads || data.threads.length === 0) {
          html += '<div class="card empty-state"><div class="icon">📭</div><p>还没有帖子，来发布第一条吧</p></div>';
        } else {
          data.threads.forEach(t => {
            const isPinned = t.pinned === 1;
            html += '<div class="card thread-item" onclick="navigate(event,\'/thread/' + t.id + '\')">';
            html += '<div class="thread-info">';
            if (isPinned) html += '<span class="pinned-badge">📌 置顶</span>';
            html += '<div class="thread-title">' + escape(t.title) + '</div>';
            html += '<div class="thread-meta">';
            html += '<span>👤 ' + escape(t.username) + '</span>';
            html += '<span>📂 ' + escape(t.category_name || '默认') + '</span>';
            html += '<span>🕐 ' + timeAgo(t.created_at) + '</span>';
            html += '</div></div>';
            html += '<div class="thread-stats">';
            html += '<div>💬 ' + (t.reply_count || 0) + '</div>';
            html += '<div>👁️ ' + t.views + '</div>';
            html += '</div></div>';
          });

          // Pagination
          if (data.totalPages > 1) {
            html += '<div class="pagination">';
            html += '<button onclick="changePage(' + (currentPage - 1) + ')" ' + (currentPage <= 1 ? 'disabled' : '') + '>上一页</button>';
            for (let i = 1; i <= data.totalPages; i++) {
              html += '<button onclick="changePage(' + i + ')" class="' + (i === currentPage ? 'active' : '') + '">' + i + '</button>';
            }
            html += '<button onclick="changePage(' + (currentPage + 1) + ')" ' + (currentPage >= data.totalPages ? 'disabled' : '') + '>下一页</button>';
            html += '</div>';
          }
        }
        html += '</div>';
        app.innerHTML = html;
      } catch (e) {
        app.innerHTML = '<div class="page"><p>加载失败</p></div>';
      }
    }

    window.changePage = function(p) {
      currentPage = p;
      renderHome();
    };

    // ===== Thread Detail =====
    async function renderThread(id) {
      const app = document.getElementById('app');
      app.innerHTML = '<div class="page">' + showLoading() + '</div>';
      try {
        const data = await api('GET', '/threads/' + id);
        const t = data.thread;
        const posts = data.posts || [];
        let html = '<div class="page">';
        html += '<a href="/" onclick="navigate(event,\'/\')" style="margin-bottom:16px;display:inline-block">← 返回首页</a>';
        html += '<div class="card">';
        html += '<div class="thread-header">';
        if (t.pinned === 1) html += '<span class="pinned-badge">📌 置顶</span> ';
        html += '<h1>' + escape(t.title) + '</h1>';
        html += '<div class="thread-meta">';
        html += '<span>👤 ' + escape(t.username) + '</span>';
        html += '<span>📂 ' + escape(t.category_name || '默认') + '</span>';
        html += '<span>🕐 ' + t.created_at + '</span>';
        html += '<span>👁️ ' + t.views + ' 次浏览</span>';
        html += '</div></div>';
        html += '<div class="thread-content">' + escape(t.content) + '</div>';
        if (currentUser && (currentUser.role === 'admin' || currentUser.id === t.user_id)) {
          html += '<div style="margin-top:16px"><button class="btn btn-danger btn-sm" onclick="deleteThread(' + t.id + ')">🗑️ 删除</button></div>';
        }
        html += '</div>';

        html += '<h3 style="margin:20px 0 12px">💬 回复 (' + posts.length + ')</h3>';
        if (posts.length === 0) {
          html += '<p style="color:var(--text2);margin-bottom:16px">暂无回复</p>';
        }
        posts.forEach(p => {
          html += '<div class="post-item">';
          html += '<div class="post-header">';
          html += '<span class="post-author">';
          html += '<span style="display:inline-block;width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,var(--primary),#a855f7);color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:600">' + escape(p.username.charAt(0).toUpperCase()) + '</span>';
          html += escape(p.username);
          if (p.role === 'admin') html += ' <span class="badge-admin">管理员</span>';
          html += '</span>';
          html += '<span style="font-size:0.8rem;color:var(--text2)">' + timeAgo(p.created_at) + '</span>';
          html += '</div>';
          html += '<div class="post-content">' + escape(p.content) + '</div>';
          if (currentUser && (currentUser.role === 'admin' || currentUser.id === p.user_id)) {
            html += '<div style="margin-top:8px"><button class="btn btn-danger btn-sm" onclick="deletePost(' + p.id + ')">删除</button></div>';
          }
          html += '</div>';
        });

        if (currentUser) {
          html += '<div class="card" style="margin-top:20px">';
          html += '<h4 style="margin-bottom:12px">发表回复</h4>';
          html += '<textarea class="form-textarea" id="replyContent" placeholder="写下你的回复..." style="margin-bottom:12px"></textarea>';
          html += '<button class="btn btn-primary" onclick="submitReply(' + id + ')">发表回复</button>';
          html += '</div>';
        }

        html += '</div>';
        app.innerHTML = html;
      } catch (e) {
        app.innerHTML = '<div class="page"><p>加载失败</p></div>';
      }
    }

    window.submitReply = async function(threadId) {
      const content = document.getElementById('replyContent').value;
      if (!content.trim()) return toast('请输入内容', 'error');
      await api('POST', '/posts', { content, thread_id: parseInt(threadId) });
      toast('回复成功');
      renderThread(threadId);
    };

    window.deleteThread = async function(id) {
      if (!confirm('确定删除此帖子？')) return;
      await api('DELETE', '/threads/' + id);
      toast('已删除');
      navigate(null, '/');
    };

    window.deletePost = async function(id) {
      if (!confirm('确定删除此回复？')) return;
      await api('DELETE', '/posts/' + id);
      toast('已删除');
      renderRoute();
    };

    // ===== New Thread =====
    async function renderNewThread() {
      if (!currentUser) { toast('请先登录', 'error'); navigate(null, '/login'); return; }
      const app = document.getElementById('app');
      let html = '<div class="page">';
      html += '<h2 style="margin-bottom:20px">📝 发布新帖</h2>';
      html += '<div class="card">';
      html += '<div class="form-group"><label>标题</label><input class="form-input" id="threadTitle" placeholder="帖子标题" maxlength="100"></div>';
      html += '<div class="form-group"><label>内容</label><textarea class="form-textarea" id="threadContent" placeholder="写下你要分享的内容..." style="min-height:180px"></textarea></div>';
      html += '<button class="btn btn-primary" onclick="submitThread()">发布帖子</button>';
      html += '</div></div>';
      app.innerHTML = html;
    }

    window.submitThread = async function() {
      const title = document.getElementById('threadTitle').value;
      const content = document.getElementById('threadContent').value;
      if (!title.trim()) return toast('请输入标题', 'error');
      if (!content.trim()) return toast('请输入内容', 'error');
      await api('POST', '/threads', { title, content, category_id: 1 });
      toast('发帖成功');
      navigate(null, '/');
    };

    // ===== Login =====
    function renderLogin() {
      const app = document.getElementById('app');
      app.innerHTML = '<div class="page auth-container">' +
        '<h2 style="text-align:center;margin-bottom:8px">👋 欢迎回来</h2>' +
        '<p style="text-align:center;color:var(--text2);margin-bottom:24px">登录或注册账号</p>' +
        '<div class="auth-tabs">' +
        '<button class="active" onclick="switchAuthTab(\'login\')">登录</button>' +
        '<button onclick="switchAuthTab(\'register\')">注册</button>' +
        '</div>' +
        '<div class="auth-error" id="authError"></div>' +
        '<div class="auth-form active" id="loginForm">' +
        '<div class="form-group"><label>用户名</label><input class="form-input" id="loginUsername" placeholder="输入用户名"></div>' +
        '<div class="form-group"><label>密码</label><input class="form-input" type="password" id="loginPassword" placeholder="输入密码"></div>' +
        '<button class="btn btn-primary" style="width:100%;justify-content:center" onclick="submitLogin()">登录</button>' +
        '</div>' +
        '<div class="auth-form" id="registerForm">' +
        '<div class="form-group"><label>用户名</label><input class="form-input" id="regUsername" placeholder="2-20个字符"></div>' +
        '<div class="form-group"><label>密码</label><input class="form-input" type="password" id="regPassword" placeholder="至少6个字符"></div>' +
        '<button class="btn btn-primary" style="width:100%;justify-content:center" onclick="submitRegister()">注册</button>' +
        '</div>' +
        '</div>';
    }

    window.switchAuthTab = function(tab) {
      document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
      document.querySelectorAll('.auth-tabs button').forEach(b => b.classList.remove('active'));
      if (tab === 'login') {
        document.getElementById('loginForm').classList.add('active');
        document.querySelector('.auth-tabs button:first-child').classList.add('active');
      } else {
        document.getElementById('registerForm').classList.add('active');
        document.querySelector('.auth-tabs button:last-child').classList.add('active');
      }
    };

    window.submitLogin = async function() {
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;
      try {
        const data = await api('POST', '/auth/login', { username, password });
        currentUser = { username: data.username, role: data.role };
        updateNav();
        toast('登录成功');
        navigate(null, '/');
      } catch (e) {}
    };

    window.submitRegister = async function() {
      const username = document.getElementById('regUsername').value;
      const password = document.getElementById('regPassword').value;
      try {
        await api('POST', '/auth/register', { username, password });
        toast('注册成功，请登录');
        switchAuthTab('login');
      } catch (e) {}
    };

    // ===== Admin =====
    let adminTab = 'dashboard';

    async function renderAdmin() {
      if (!currentUser || currentUser.role !== 'admin') {
        toast('无权访问', 'error');
        navigate(null, '/');
        return;
      }
      const app = document.getElementById('app');
      app.innerHTML = '<div class="page"><h2 style="margin-bottom:8px">⚙️ 管理面板</h2><p style="color:var(--text2);margin-bottom:20px">论坛管理控制台</p>' +
        '<div class="admin-sidebar">' +
        '<button class="active" onclick="switchAdminTab(\'dashboard\')">📊 概览</button>' +
        '<button onclick="switchAdminTab(\'users\')">👥 用户</button>' +
        '<button onclick="switchAdminTab(\'threads\')">📋 帖子</button>' +
        '</div><div id="adminContent">' + showLoading() + '</div></div>';
      renderAdminDashboard();
    }

    window.switchAdminTab = function(tab) {
      adminTab = tab;
      document.querySelectorAll('.admin-sidebar button').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.admin-sidebar button').forEach(b => {
        if ((tab === 'dashboard' && b.textContent.includes('概览')) ||
            (tab === 'users' && b.textContent.includes('用户')) ||
            (tab === 'threads' && b.textContent.includes('帖子'))) b.classList.add('active');
      });
      if (tab === 'dashboard') renderAdminDashboard();
      else if (tab === 'users') renderAdminUsers();
      else if (tab === 'threads') renderAdminThreads();
    };

    async function renderAdminDashboard() {
      const el = document.getElementById('adminContent');
      el.innerHTML = showLoading();
      try {
        const stats = await api('GET', '/admin/stats');
        let html = '<div class="admin-stats">';
        html += '<div class="stat-card"><div class="stat-number">' + stats.users + '</div><div class="stat-label">用户数</div></div>';
        html += '<div class="stat-card"><div class="stat-number">' + stats.threads + '</div><div class="stat-label">帖子数</div></div>';
        html += '<div class="stat-card"><div class="stat-number">' + stats.posts + '</div><div class="stat-label">回复数</div></div>';
        html += '</div>';
        html += '<div class="card"><h4 style="margin-bottom:12px">最近注册</h4>';
        if (stats.recentUsers && stats.recentUsers.length > 0) {
          html += '<table class="admin-table"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>注册时间</th></tr></thead><tbody>';
          stats.recentUsers.forEach(u => {
            html += '<tr><td>' + u.id + '</td><td>' + escape(u.username) + '</td><td>' + (u.role === 'admin' ? '<span class="badge-admin">管理员</span>' : '用户') + '</td><td>' + u.created_at + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        html += '</div>';
        el.innerHTML = html;
      } catch (e) { el.innerHTML = '<p>加载失败</p>'; }
    }

    async function renderAdminUsers() {
      const el = document.getElementById('adminContent');
      el.innerHTML = showLoading();
      try {
        const users = await api('GET', '/admin/users');
        let html = '<div class="card"><h4 style="margin-bottom:12px">👥 用户管理</h4>';
        html += '<table class="admin-table"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>注册时间</th><th>操作</th></tr></thead><tbody>';
        users.forEach(u => {
          html += '<tr><td>' + u.id + '</td><td>' + escape(u.username) + '</td><td>' + (u.role === 'admin' ? '<span class="badge-admin">管理员</span>' : '用户') + '</td><td>' + u.created_at + '</td><td>';
          if (u.id !== currentUser.id) {
            if (u.role !== 'admin') {
              html += '<button class="btn btn-sm" onclick="setRole(' + u.id + ',\'admin\')">设为管理员</button> ';
            } else {
              html += '<button class="btn btn-sm" onclick="setRole(' + u.id + ',\'user\')">设为用户</button> ';
            }
            html += '<button class="btn btn-danger btn-sm" onclick="deleteUser(' + u.id + ')">删除</button>';
          } else {
            html += '<span style="color:var(--text2)">当前用户</span>';
          }
          html += '</td></tr>';
        });
        html += '</tbody></table></div>';
        el.innerHTML = html;
      } catch (e) { el.innerHTML = '<p>加载失败</p>'; }
    }

    window.setRole = async function(userId, role) {
      await api('POST', '/admin/set-role', { user_id: userId, role });
      toast('角色已更新');
      renderAdminUsers();
    };

    window.deleteUser = async function(userId) {
      if (!confirm('确定删除此用户？其所有内容将被匿名化。')) return;
      await api('DELETE', '/admin/users/' + userId);
      toast('用户已删除');
      renderAdminUsers();
    };

    async function renderAdminThreads() {
      const el = document.getElementById('adminContent');
      el.innerHTML = showLoading();
      try {
        const data = await api('GET', '/threads?page=1');
        let html = '<div class="card"><h4 style="margin-bottom:12px">📋 帖子管理</h4>';
        html += '<table class="admin-table"><thead><tr><th>ID</th><th>标题</th><th>作者</th><th>回复</th><th>时间</th><th>操作</th></tr></thead><tbody>';
        data.threads.forEach(t => {
          html += '<tr><td>' + t.id + '</td><td>' + escape(t.title).substring(0, 30) + '</td><td>' + escape(t.username) + '</td><td>' + (t.reply_count || 0) + '</td><td>' + timeAgo(t.created_at) + '</td><td>';
          html += '<button class="btn btn-danger btn-sm" onclick="adminDeleteThread(' + t.id + ')">删除</button>';
          html += '</td></tr>';
        });
        html += '</tbody></table></div>';
        el.innerHTML = html;
      } catch (e) { el.innerHTML = '<p>加载失败</p>'; }
    }

    window.adminDeleteThread = async function(id) {
      if (!confirm('确定删除此帖子及相关回复？')) return;
      await api('DELETE', '/threads/' + id);
      toast('已删除');
      renderAdminThreads();
    };

    // ===== Init =====
    updateNav();
    renderRoute();
  </script>
</body>
</html>`;
}

// ---------- 主处理器 ----------
export default {
  async fetch(request, env, ctx) {
    try {
      await initDatabase(env);
    } catch (e) {}

    const url = new URL(request.url);
    const path = url.pathname;

    // API 路由
    if (path.startsWith('/api/')) {
      const apiPath = path.replace('/api', '');
      const method = request.method;
      let body = {};
      if (['POST', 'PUT', 'DELETE'].includes(method)) {
        try { body = await request.json(); } catch (e) {}
      }

      // Auth
      if (apiPath === '/auth/register' && method === 'POST') return handleRegister(env, body);
      if (apiPath === '/auth/login' && method === 'POST') return handleLogin(env, body);
      if (apiPath === '/auth/logout' && method === 'POST') return handleLogout(env, request);
      if (apiPath === '/me' && method === 'GET') return handleMe(env, request);

      // Categories
      if (apiPath === '/categories' && method === 'GET') return handleCategories(env);

      // Threads
      if (apiPath === '/threads' && method === 'GET') return handleThreads(env, request);
      if (apiPath.match(/^\/threads\/\d+$/) && method === 'GET') {
        const id = apiPath.split('/')[2];
        return handleThreadDetail(env, id);
      }
      if (apiPath === '/threads' && method === 'POST') return handleCreateThread(env, request, body);
      if (apiPath.match(/^\/threads\/\d+$/) && method === 'DELETE') {
        const id = apiPath.split('/')[2];
        return handleDeleteThread(env, request, id);
      }

      // Posts
      if (apiPath === '/posts' && method === 'POST') return handleCreatePost(env, request, body);
      if (apiPath.match(/^\/posts\/\d+$/) && method === 'DELETE') {
        const id = apiPath.split('/')[2];
        return handleDeletePost(env, request, id);
      }

      // Admin
      if (apiPath === '/admin/stats' && method === 'GET') return handleAdminStats(env, request);
      if (apiPath === '/admin/users' && method === 'GET') return handleAdminUsers(env, request);
      if (apiPath === '/admin/set-role' && method === 'POST') return handleAdminSetRole(env, request, body);
      if (apiPath.match(/^\/admin\/users\/\d+$/) && method === 'DELETE') {
        const id = apiPath.split('/')[3];
        return handleAdminDeleteUser(env, request, id);
      }

      return json({ error: 'Not Found' }, 404);
    }

    // 前端页面
    const user = await getCurrentUser(env, request);
    const html = renderFrontend(user, path);
    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
};
