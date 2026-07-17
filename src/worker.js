// ─── NW Forum · 完整 Worker ───
function hasDB(e){return !!(e&&e.db)}

async function initDB(e){
  if(!hasDB(e)) return;
  try{await e.db.exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT DEFAULT 'user',created_at TEXT DEFAULT (datetime('now')));CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE NOT NULL,description TEXT DEFAULT '');CREATE TABLE IF NOT EXISTS threads(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,content TEXT NOT NULL,user_id INTEGER NOT NULL,category_id INTEGER DEFAULT 1,pinned INTEGER DEFAULT 0,views INTEGER DEFAULT 0,created_at TEXT DEFAULT (datetime('now')),updated_at TEXT DEFAULT (datetime('now')));CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY AUTOINCREMENT,content TEXT NOT NULL,user_id INTEGER NOT NULL,thread_id INTEGER NOT NULL,created_at TEXT DEFAULT (datetime('now')));CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL);INSERT OR IGNORE INTO categories(id,name,description)VALUES(1,'默认版块','默认讨论版块')")}
  catch(e){console.error(e)}
}

async function hashPw(p){
  var s=crypto.getRandomValues(new Uint8Array(16)),k=await crypto.subtle.importKey('raw',new TextEncoder().encode(p),'PBKDF2',false,['deriveBits']),
  b=await crypto.subtle.deriveBits({name:'PBKDF2',salt:s,iterations:1e5,hash:'SHA-256'},k,256),
  h=btoa(String.fromCharCode(...new Uint8Array(b)));
  return btoa(String.fromCharCode(...s))+':'+h
}
async function verPw(p,st){
  var a=st.split(':'),s=new Uint8Array([...atob(a[0])].map(function(c){return c.charCodeAt(0)})),
  k=await crypto.subtle.importKey('raw',new TextEncoder().encode(p),'PBKDF2',false,['deriveBits']),
  b=await crypto.subtle.deriveBits({name:'PBKDF2',salt:s,iterations:1e5,hash:'SHA-256'},k,256);
  return btoa(String.fromCharCode(...new Uint8Array(b)))===a[1]
}
function genT(){return Array.from(crypto.getRandomValues(new Uint8Array(32)),function(b){return b.toString(16).padStart(2,'0')}).join('')}
function sanit(s){return typeof s!='string'?'':s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function parC(c){var o={};if(c)c.split(';').forEach(function(x){var p=x.trim().split('=');if(p.length>=2)o[p[0]]=p.slice(1).join('=')});return o}
function setC(t){return 'nw_forum_token='+t+'; HttpOnly; Secure; Path=/; SameSite=Lax; Expires='+new Date(Date.now()+7*864e5).toUTCString()}
function clrC(){return 'nw_forum_token=; HttpOnly; Secure; Path=/; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT'}
function json(d,s){return new Response(JSON.stringify(d),{status:s||200,headers:{'Content-Type':'application/json; charset=utf-8'}})}

async function getU(e,r){
  if(!hasDB(e))return null;
  var t=parC(r.headers.get('Cookie')||'')['nw_forum_token'];
  if(!t)return null;
  try{return await e.db.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires_at>datetime('now')").bind(t).first()||null}
  catch(er){return null}
}

// API handlers
async function apiReg(e,b){
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  var u=b.username,p=b.password;
  if(!u||!p||u.length<2||u.length>20||p.length<6)return json({error:'用户名2-20字符，密码至少6字符'},400);
  if(!/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(u))return json({error:'用户名只允许字母、数字、下划线和中文'},400);
  try{
    if(await e.db.prepare('SELECT id FROM users WHERE username=?').bind(u).first())return json({error:'用户名已存在'},409);
    var ph=await hashPw(p),c=await e.db.prepare('SELECT COUNT(*)as c FROM users').first(),r=(c&&c.c===0)?'admin':'user';
    await e.db.prepare('INSERT INTO users(username,password_hash,role)VALUES(?,?,?)').bind(u,ph,r).run();
    return json({message:'注册成功',role:r})
  }catch(er){return json({error:'注册失败'},500)}
}

async function apiLog(e,b){
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  var u=b.username,p=b.password;
  if(!u||!p)return json({error:'请填写用户名和密码'},400);
  try{
    var us=await e.db.prepare('SELECT * FROM users WHERE username=?').bind(u).first();
    if(!us||!(await verPw(p,us.password_hash)))return json({error:'用户名或密码错误'},401);
    var t=genT(),h=new Headers({'Content-Type':'application/json'});
    h.append('Set-Cookie',setC(t));
    await e.db.prepare("INSERT INTO sessions(user_id,token,expires_at)VALUES(?,?,datetime('now','+7 days'))").bind(us.id,t).run();
    return new Response(JSON.stringify({message:'登录成功',username:us.username,role:us.role}),{status:200,headers:h})
  }catch(er){return json({error:'登录失败'},500)}
}

async function apiOut(e,r){
  if(!hasDB(e)){var h=new Headers();h.append('Set-Cookie',clrC());h.append('Content-Type','application/json');return new Response(JSON.stringify({message:'已登出'}),{headers:h})}
  var t=parC(r.headers.get('Cookie')||'')['nw_forum_token'];
  if(t)try{await e.db.prepare('DELETE FROM sessions WHERE token=?').bind(t).run()}catch(er){}
  var h=new Headers({'Content-Type':'application/json'});h.append('Set-Cookie',clrC());
  return new Response(JSON.stringify({message:'已登出'}),{headers:h})
}

async function apiMe(e,r){var u=await getU(e,r);if(!u)return json({error:'未登录'},401);return json({user:{id:u.id,username:u.username,role:u.role}})}

async function apiThr(e,r){
  if(!hasDB(e))return json({threads:[],total:0,page:1,totalPages:0});
  var u=new URL(r.url),p=Math.max(1,parseInt(u.searchParams.get('page'))||1),l=20,o=(p-1)*l;
  try{
    var cnt=await e.db.prepare('SELECT COUNT(*)as total FROM threads').first();
    var t=cnt?cnt.total:0;
    var rows=await e.db.prepare('SELECT t.id,t.title,t.user_id,t.pinned,t.views,t.created_at,t.updated_at,u.username,(SELECT COUNT(*)FROM posts WHERE thread_id=t.id)as reply_count,c.name as category_name FROM threads t JOIN users u ON t.user_id=u.id LEFT JOIN categories c ON t.category_id=c.id ORDER BY t.pinned DESC,t.updated_at DESC LIMIT ? OFFSET ?').bind(l,o).all();
    return json({threads:rows.results||[],total:t,page:p,totalPages:Math.ceil(t/l)})
  }catch(er){return json({threads:[],total:0,page:1,totalPages:0})}
}

async function apiThrD(e,id){
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{
    var t=await e.db.prepare('SELECT t.*,u.username,c.name as category_name FROM threads t JOIN users u ON t.user_id=u.id LEFT JOIN categories c ON t.category_id=c.id WHERE t.id=?').bind(id).first();
    if(!t)return json({error:'帖子不存在'},404);
    await e.db.prepare('UPDATE threads SET views=views+1 WHERE id=?').bind(id).run();
    var ps=await e.db.prepare('SELECT p.*,u.username,u.role FROM posts p JOIN users u ON p.user_id=u.id WHERE p.thread_id=? ORDER BY p.created_at ASC').bind(id).all();
    return json({thread:t,posts:ps.results||[]})
  }catch(er){return json({error:'查询失败'},500)}
}

async function apiCThr(e,r,b){
  var u=await getU(e,r);if(!u)return json({error:'请先登录'},401);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  if(!b.title||!b.content)return json({error:'标题和内容不能为空'},400);
  if(b.title.length>100)return json({error:'标题不能超过100字符'},400);
  try{
    var re=await e.db.prepare('INSERT INTO threads(title,content,user_id)VALUES(?,?,?)').bind(sanit(b.title),sanit(b.content),u.id).run();
    return json({message:'发帖成功',id:re.meta.last_row_id},201)
  }catch(er){return json({error:'发帖失败'},500)}
}

async function apiCPo(e,r,b){
  var u=await getU(e,r);if(!u)return json({error:'请先登录'},401);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  if(!b.content)return json({error:'内容不能为空'},400);
  try{
    if(!await e.db.prepare('SELECT id FROM threads WHERE id=?').bind(b.thread_id).first())return json({error:'帖子不存在'},404);
    await e.db.prepare('INSERT INTO posts(content,user_id,thread_id)VALUES(?,?,?)').bind(sanit(b.content),u.id,b.thread_id).run();
    await e.db.prepare("UPDATE threads SET updated_at=datetime('now') WHERE id=?").bind(b.thread_id).run();
    return json({message:'回复成功'},201)
  }catch(er){return json({error:'回复失败'},500)}
}

async function apiDTh(e,r,id){
  var u=await getU(e,r);if(!u)return json({error:'未登录'},401);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{
    var t=await e.db.prepare('SELECT user_id FROM threads WHERE id=?').bind(id).first();
    if(!t)return json({error:'帖子不存在'},404);
    if(u.role!=='admin'&&t.user_id!==u.id)return json({error:'无权操作'},403);
    await e.db.prepare('DELETE FROM posts WHERE thread_id=?').bind(id).run();
    await e.db.prepare('DELETE FROM threads WHERE id=?').bind(id).run();
    return json({message:'删除成功'})
  }catch(er){return json({error:'删除失败'},500)}
}

async function apiDPo(e,r,id){
  var u=await getU(e,r);if(!u)return json({error:'未登录'},401);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{
    var p=await e.db.prepare('SELECT user_id FROM posts WHERE id=?').bind(id).first();
    if(!p)return json({error:'回复不存在'},404);
    if(u.role!=='admin'&&p.user_id!==u.id)return json({error:'无权操作'},403);
    await e.db.prepare('DELETE FROM posts WHERE id=?').bind(id).run();
    return json({message:'删除成功'})
  }catch(er){return json({error:'删除失败'},500)}
}

async function apiAS(e,r){
  var u=await getU(e,r);if(!u||u.role!=='admin')return json({error:'无权访问'},403);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{
    var uc=await e.db.prepare('SELECT COUNT(*)as c FROM users').first(),tc=await e.db.prepare('SELECT COUNT(*)as c FROM threads').first(),pc=await e.db.prepare('SELECT COUNT(*)as c FROM posts').first(),ru=await e.db.prepare('SELECT id,username,role,created_at FROM users ORDER BY created_at DESC LIMIT 5').all();
    return json({users:uc.c,threads:tc.c,posts:pc.c,recentUsers:ru.results||[]})
  }catch(er){return json({error:'查询失败'},500)}
}

async function apiAU(e,r){
  var u=await getU(e,r);if(!u||u.role!=='admin')return json({error:'无权访问'},403);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{var rows=await e.db.prepare('SELECT id,username,role,created_at FROM users ORDER BY id').all();return json(rows.results||[])}
  catch(er){return json({error:'查询失败'},500)}
}

async function apiASR(e,r,b){
  var u=await getU(e,r);if(!u||u.role!=='admin')return json({error:'无权访问'},403);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  if(!['user','admin'].includes(b.role))return json({error:'无效角色'},400);
  try{await e.db.prepare('UPDATE users SET role=? WHERE id=?').bind(b.role,b.user_id).run();return json({message:'角色已更新'})}
  catch(er){return json({error:'更新失败'},500)}
}

async function apiAD(e,r,id){
  var u=await getU(e,r);if(!u||u.role!=='admin')return json({error:'无权访问'},403);
  if(parseInt(id)===u.id)return json({error:'不能删除自己'},400);
  if(!hasDB(e))return json({error:'数据库未配置'},503);
  try{await e.db.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run();await e.db.prepare('DELETE FROM posts WHERE user_id=?').bind(id).run();await e.db.prepare('DELETE FROM threads WHERE user_id=?').bind(id).run();await e.db.prepare('DELETE FROM users WHERE id=?').bind(id).run();return json({message:'用户已删除'})}
  catch(er){return json({error:'删除失败'},500)}
}

// ─── 前端 ───
function htmlPage(user) {
  var uj = JSON.stringify(user ? {id:user.id, username:user.username, role:user.role} : null);
  return '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width,initial-scale=1.0">\n<title>NW Forum</title>\n<style>\n'
+'body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f7fa;color:#1a1a2e;line-height:1.6}\n'
+'.nav{background:#fff;border-bottom:1px solid #e5e7eb;padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.08)}\n'
+'.nav a{color:#6366f1;text-decoration:none;padding:8px 16px;border-radius:8px;transition:.2s;font-size:.875rem}\n'
+'.nav a:hover{background:#f0f2f5}\n'
+'.nav .lg{font-size:1.2rem;font-weight:700;background:linear-gradient(135deg,#6366f1,#a855f7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}\n'
+'.nav-r{display:flex;align-items:center;gap:8px}\n'
+'.con{max-width:960px;margin:0 auto;padding:24px 16px}\n'
+'.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.08);border:1px solid #e5e7eb;margin-bottom:12px}\n'
+'.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 20px;border:none;border-radius:8px;font-size:.875rem;cursor:pointer;transition:.2s;font-family:inherit;background:#f0f2f5;color:#1a1a2e}\n'
+'.btn:hover{transform:translateY(-1px);box-shadow:0 8px 32px rgba(0,0,0,.1)}\n'
+'.btn-p{background:#6366f1;color:#fff}.btn-p:hover{background:#4f46e5}\n'
+'.btn-d{background:#ef4444;color:#fff}.btn-d:hover{background:#dc2626}\n'
+'.btn-sm{padding:6px 12px;font-size:.8rem}\n'
+'.inp{width:100%;padding:10px 14px;border:2px solid #e5e7eb;border-radius:8px;font-size:.9rem;transition:.2s;outline:none;font-family:inherit;box-sizing:border-box}\n'
+'.inp:focus,.ta:focus{border-color:#6366f1;box-shadow:0 0 0 3px #eef2ff}\n'
+'.ta{width:100%;padding:10px 14px;border:2px solid #e5e7eb;border-radius:8px;font-size:.9rem;transition:.2s;outline:none;font-family:inherit;min-height:120px;resize:vertical;box-sizing:border-box}\n'
+'.fg{margin-bottom:16px}.fg label{display:block;font-size:.875rem;font-weight:500;margin-bottom:6px;color:#6b7280}\n'
+'.ti{font-size:1.05rem;font-weight:600;color:#1a1a2e;cursor:pointer}\n'
+'.ti:hover{color:#6366f1}\n'
+'.mt{font-size:.8rem;color:#6b7280;display:flex;gap:16px;flex-wrap:wrap;margin-top:4px}\n'
+'.pg{animation:fade .3s ease}@keyframes fade{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}\n'
+'.ld{text-align:center;padding:40px;color:#6b7280}\n'
+'.sp{width:32px;height:32px;border:3px solid #e5e7eb;border-top-color:#6366f1;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 12px}\n'
+'.ep{text-align:center;padding:60px 20px;color:#6b7280}@keyframes spin{to{transform:rotate(360deg)}}\n'
+'.badge{background:#ef4444;color:#fff;padding:2px 8px;border-radius:99px;font-size:.7rem;font-weight:600;margin-left:6px}\n'
+'.pj{border-left:3px solid #6366f1;background:#f0f2f5;border-radius:0 8px 8px 0;padding:16px;margin-bottom:12px}\n'
+'.pj .ph{display:flex;justify-content:space-between;font-size:.85rem;margin-bottom:8px}\n'
+'.pc{white-space:pre-wrap;word-break:break-word;font-size:.9rem}\n'
+'.th{font-size:1.5rem;margin-bottom:8px}.thc{white-space:pre-wrap;word-break:break-word;font-size:.95rem}\n'
+'.not{text-align:center;padding:60px 20px;color:#6b7280}\n'
+'.ts{position:fixed;top:80px;right:20px;z-index:300;display:flex;flex-direction:column;gap:8px}\n'
+'.to{background:#fff;padding:12px 20px;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,.1);font-size:.875rem;border-left:4px solid #6366f1;max-width:320px;animation:sl .3s ease}\n'
+'.to.e{border-left-color:#ef4444}.to.s{border-left-color:#22c55e}@keyframes sl{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}\n'
+'.pg2{display:flex;justify-content:center;gap:8px;margin-top:24px}\n'
+'.pg2 button{padding:8px 14px;border:1px solid #e5e7eb;background:#fff;border-radius:8px;cursor:pointer;font-family:inherit;font-size:.85rem}\n'
+'.pg2 button:hover{background:#f0f2f5}.pg2 button.a{background:#6366f1;color:#fff;border-color:#6366f1}\n'
+'.pg2 button:disabled{opacity:.4;cursor:not-allowed}.thr{border-bottom:1px solid #e5e7eb;padding:16px 0;cursor:pointer;display:flex;gap:16px}.thr:last-child{border-bottom:none}\n'
+'.thr:hover{padding-left:8px}.ti2{flex:1;min-width:0}.ts2{text-align:right;flex-shrink:0;color:#6b7280;font-size:.85rem}\n'
+'.st{display:grid;gap:12px;margin-bottom:24px}.st .c{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px;text-align:center}.st .n{font-size:2rem;font-weight:700;color:#6366f1}.st .l{font-size:.85rem;color:#6b7280;margin-top:4px}\n'
+'.ab{display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap}.ab button{padding:10px 20px;border:2px solid #e5e7eb;background:#fff;border-radius:8px;cursor:pointer;font-family:inherit;font-size:.85rem;color:#6b7280;font-weight:500}\n'
+'.ab button:hover{border-color:#6366f1}.ab button.a{background:#6366f1;color:#fff;border-color:#6366f1}\n'
+'.tbl{width:100%;border-collapse:collapse;font-size:.85rem}.tbl th{text-align:left;padding:12px 8px;border-bottom:2px solid #e5e7eb;color:#6b7280;font-weight:600}.tbl td{padding:10px 8px;border-bottom:1px solid #e5e7eb}.tbl tr:hover td{background:#f0f2f5}\n'
+'.au{max-width:420px;margin:60px auto}.at{display:flex;margin-bottom:24px;background:#f0f2f5;border-radius:8px;overflow:hidden}.at button{flex:1;padding:12px;border:none;background:transparent;font-size:.9rem;cursor:pointer;color:#6b7280;font-family:inherit}.at button.a{background:#6366f1;color:#fff}\n'
+'.af{display:none}.af.a{display:block}@media(max-width:640px){.nav{padding:0 12px}.con{padding:16px 12px}.au{margin:30px auto}.ts2{display:none}}\n'
+'</style>\n</head>\n<body>\n'
+'<nav class="nav"><a href="/" class="lg">NW Forum</a><div class="nav-r">'
+'<span id="nu" style="display:none"><span id="navA" style="display:inline-flex;width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#a855f7);color:#fff;align-items:center;justify-content:center;font-weight:600;font-size:.8rem;margin-right:6px">U</span><span id="navU"></span><span class="badge" id="navB" style="display:none">管理员</span></span>'
+'<a href="/" onclick="return nav(event,\'/\')">首页</a><a href="/new" onclick="return nav(event,\'/new\')" id="nNew" style="display:none">发帖</a><a href="/admin" onclick="return nav(event,\'/admin\')" id="nAdm" style="display:none">管理</a><a href="/login" onclick="return nav(event,\'/login\')" id="nLog">登录</a>'
+'<button id="nOut" style="display:none" class="btn btn-sm" onclick="lgout()">登出</button>'
+'</div></nav>\n'
+'<div class="ts" id="tss"></div>\n'
+'<main class="con" id="app"><div class="ld"><div class="sp"></div><p>加载中...</p></div></main>\n'
+'<script>\n(function(){\n'
+'var CU='+uj+';\n'
+'var cp=1,ap="dashboard";\n'
+'function esc(s){var d=document.createElement("div");d.textContent=s||"";return d.innerHTML}\n'
+'function to(msg,ty){var c=document.getElementById("tss"),d=document.createElement("div");d.className="to "+(ty==="error"?"e":"s");d.textContent=msg;c.appendChild(d);setTimeout(function(){d.remove()},3e3)}\n'
+'function api(m,p,b){var o={method:m,headers:{}};if(b){o.headers["Content-Type"]="application/json";o.body=JSON.stringify(b)}return fetch("/api"+p,o).then(function(r){return r.json().then(function(d){if(!r.ok&&d.error)throw new Error(d.error);return d})})}\n'
+'function nv(e,p){e&&e.preventDefault();history.pushState(null,"",p);rt()}\n'
+'window.addEventListener("popstate",rt);\n'
+'function nav(e,p){return nv(e,p),false}\n'
+'function upd(){var lo=document.getElementById("nLog"),lo2=document.getElementById("nOut"),nu=document.getElementById("nu"),nn=document.getElementById("nNew"),na=document.getElementById("nAdm");if(CU){lo.style.display="none";lo2.style.display="";nu.style.display="";document.getElementById("navA").textContent=CU.username.charAt(0).toUpperCase();document.getElementById("navU").textContent=CU.username;document.getElementById("navB").style.display=CU.role==="admin"?"":"none";nn.style.display="";na.style.display=CU.role==="admin"?"":"none"}else{lo.style.display="";lo2.style.display="none";nu.style.display="none";nn.style.display="none";na.style.display="none"}}\n'
+'function lgout(){api("POST","/auth/logout").then(function(){CU=null;upd();nv(null,"/")}).catch(function(e){})}\n'
+'function ago(d){var dt=new Date(d+"Z"),s=Math.floor((new Date()-dt)/1e3);if(s<60)return"刚刚";var m=Math.floor(s/60);if(m<60)return m+"分钟前";var h=Math.floor(m/60);if(h<24)return h+"小时前";var dy=Math.floor(h/24);if(dy<30)return dy+"天前";return(d||"").split(" ")[0]}\n'
+'function rt(){var p=window.location.pathname;if(p==="/login")pgL();else if(p==="/new")pgN();else if(p==="/admin")pgA();else if(p.indexOf("/thread/")===0)pgT(p.split("/")[2]);else pgH()}\n'
+'function pgH(){var a=document.getElementById("app");a.innerHTML=\'<div class="pg"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px"><h2> 全部帖子</h2>\'+(CU?\'<button class="btn btn-p" onclick="return nv(event,\'/new\')">+ 发新帖</button>\':"")+\'</div><div class="ld"><div class="sp"></div><p>加载中...</p></div></div>\';api("GET","/threads?page="+cp).then(function(d){var h=\'<div class="pg"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px"><h2> 全部帖子</h2>\'+(CU?\'<button class="btn btn-p" onclick="return nv(event,\'/new\')">+ 发新帖</button>\':"")+\'</div>\';if(!d.threads||d.threads.length===0){h+=\'<div class="not"><p>还没有帖子</p></div>\'}else{d.threads.forEach(function(t){h+=\'<div class="card thr" onclick="nv(event,\'/thread/\'+t.id+\')\'"><div class="ti2"><div class="ti">\'+esc(t.title)+\'</div><div class="mt"><span>\'+esc(t.username)+\'</span><span>\'+ (t.category_name||"默认")+\'</span><span>\'+ago(t.created_at)+\'</span></div></div><div class="ts2"><div> &#x1f4ac;\'+(t.reply_count||0)+\'</div><div> &#x1f441;\'+t.views+\'</div></div></div>\'});if(d.totalPages>1){h+=\'<div class="pg2">\';h+=\'<button onclick="cp=\'+(cp-1)+\';pgH()" \'+(cp<=1?"disabled":"")+\'>上一页</button>\';for(var i=1;i<=d.totalPages;i++)h+=\'<button onclick="cp=\'+i+\';pgH()" class="\'+(i===cp?"a":"")+\'">\'+i+\'</button>\';h+=\'<button onclick="cp=\'+(cp+1)+\';pgH()" \'+(cp>=d.totalPages?"disabled":"")+\'>下一页</button></div>\'}}a.innerHTML=h}).catch(function(e){a.innerHTML=\'<div class="pg"><div class="card not"><p>数据库未配置，请在 Cloudflare Dashboard 绑定 D1 数据库</p></div></div>\'})}\n'
+'function pgT(id){var a=document.getElementById("app");a.innerHTML=\'<div class="pg"><div class="ld"><div class="sp"></div><p>加载中...</p></div></div>\';api("GET","/threads/"+id).then(function(d){var t=d.thread,ps=d.posts||[];var h=\'<div class="pg"><a href="/" onclick="return nv(event,\'/\')" style="margin-bottom:12px;display:inline-block"> 返回首页</a>\';h+=\'<div class="card"><div class="th">\'+esc(t.title)+\'</div><div class="mt" style="margin-bottom:12px"><span>\'+esc(t.username)+\'</span><span>\'+t.created_at+\'</span><span> &#x1f441;\'+t.views+\'次浏览</span></div><div class="thc">\'+esc(t.content)+\'</div>\';if(CU&&(CU.role==="admin"||CU.id===t.user_id))h+=\'<div style="margin-top:12px"><button class="btn btn-d btn-sm" onclick="delThr(\'+t.id+\')"> 删除</button></div>\';h+=\'</div><h3 style="margin:20px 0 12px"> 回复 (\'+ps.length+\')</h3>\';if(ps.length===0)h+=\'<p style="color:#6b7280;margin-bottom:16px">暂无回复</p>\';ps.forEach(function(p){h+=\'<div class="pj"><div class="ph"><span style="font-weight:600">\'+esc(p.username)+(p.role==="admin"?\' <span class="badge">管理员</span>\':"")+\'</span><span style="color:#6b7280;font-size:.8rem">\'+ago(p.created_at)+\'</span></div><div class="pc">\'+esc(p.content)+\'</div>\';if(CU&&(CU.role==="admin"||CU.id===p.user_id))h+=\'<div style="margin-top:8px"><button class="btn btn-d btn-sm" onclick="delPo(\'+p.id+\')"> 删除</button></div>\';h+=\'</div>\'});if(CU){h+=\'<div class="card"><h4 style="margin-bottom:12px">发表回复</h4><textarea class="ta" id="rp" placeholder="回复内容..." style="margin-bottom:12px"></textarea><button class="btn btn-p" onclick="rep(\'+id+\')">发表回复</button></div>\'}h+=\'</div>\';a.innerHTML=h}).catch(function(e){a.innerHTML=\'<div class="pg"><p>加载失败</p></div>\'})}\n'
+'function rep(id){var c=document.getElementById("rp").value;if(!c.trim())return to("请输入内容","error");api("POST","/posts",{content:c,thread_id:parseInt(id)}).then(function(){to("回复成功");pgT(id)}).catch(function(e){})}\n'
+'function delThr(id){if(!confirm("确定删除？"))return;api("DELETE","/threads/"+id).then(function(){to("已删除");nv(null,"/")}).catch(function(e){})}\n'
+'function delPo(id){if(!confirm("确定删除？"))return;api("DELETE","/posts/"+id).then(function(){to("已删除");rt()}).catch(function(e){})}\n'
+'function pgN(){if(!CU){to("请先登录","error");nv(null,"/login");return}var a=document.getElementById("app");a.innerHTML=\'<div class="pg"><h2 style="margin-bottom:20px"> 发布新帖</h2><div class="card"><div class="fg"><label>标题</label><input class="inp" id="tT" placeholder="帖子标题" maxlength="100"></div><div class="fg"><label>内容</label><textarea class="ta" id="tC" placeholder="写下内容..." style="min-height:180px"></textarea></div><button class="btn btn-p" onclick="nThr()">发布帖子</button></div></div>\'}\n'
+'function nThr(){var ti=document.getElementById("tT").value,co=document.getElementById("tC").value;if(!ti.trim())return to("请输入标题","error");if(!co.trim())return to("请输入内容","error");api("POST","/threads",{title:ti,content:co}).then(function(){to("发帖成功");nv(null,"/")}).catch(function(e){})}\n'
+'function pgL(){var a=document.getElementById("app");a.innerHTML=\'<div class="pg au"><h2 style="text-align:center;margin-bottom:8px"> 欢迎回来</h2><p style="text-align:center;color:#6b7280;margin-bottom:24px">登录或注册</p><div class="at"><button class="a" onclick="swA(\'l\')">登录</button><button onclick="swA(\'r\')">注册</button></div><div class="af a" id="lf"><div class="fg"><label>用户名</label><input class="inp" id="lU"></div><div class="fg"><label>密码</label><input class="inp" type="password" id="lP"></div><button class="btn btn-p" style="width:100%;justify-content:center" onclick="doL()">登录</button></div><div class="af" id="rf"><div class="fg"><label>用户名</label><input class="inp" id="rU" placeholder="2-20个字符"></div><div class="fg"><label>密码</label><input class="inp" type="password" id="rP" placeholder="至少6个字符"></div><button class="btn btn-p" style="width:100%;justify-content:center" onclick="doR()">注册</button></div></div>\'}\n'
+'function swA(t){document.querySelectorAll(".af").forEach(function(f){f.classList.remove("a")});document.querySelectorAll(".at button").forEach(function(b){b.classList.remove("a")});if(t==="l"){document.getElementById("lf").classList.add("a");document.querySelector(".at button:first-child").classList.add("a")}else{document.getElementById("rf").classList.add("a");document.querySelector(".at button:last-child").classList.add("a")}}\n'
+'function doL(){var u=document.getElementById("lU").value,p=document.getElementById("lP").value;api("POST","/auth/login",{username:u,password:p}).then(function(d){CU={id:d.id||0,username:d.username,role:d.role};upd();to("登录成功");nv(null,"/")}).catch(function(e){})}\n'
+'function doR(){var u=document.getElementById("rU").value,p=document.getElementById("rP").value;api("POST","/auth/register",{username:u,password:p}).then(function(){to("注册成功，请登录");swA("l")}).catch(function(e){})}\n'
+'function pgA(){if(!CU||CU.role!=="admin"){to("无权访问","error");nv(null,"/");return}var a=document.getElementById("app");a.innerHTML=\'<div class="pg"><h2> 管理面板</h2><p style="color:#6b7280;margin-bottom:20px">论坛管理</p><div class="ab"><button class="a" onclick="swAd(\'d\')"> 概览</button><button onclick="swAd(\'u\')"> 用户</button><button onclick="swAd(\'t\')"> 帖子</button></div><div id="adC"><div class="ld"><div class="sp"></div><p>加载中...</p></div></div></div>\';pgAdD()}\n'
+'function swAd(t){ap=t;document.querySelectorAll(".ab button").forEach(function(b){b.classList.remove("a")});document.querySelectorAll(".ab button").forEach(function(b){if((t==="d"&&b.textContent.indexOf("概览")!==-1)||(t==="u"&&b.textContent.indexOf("用户")!==-1)||(t==="t"&&b.textContent.indexOf("帖子")!==-1))b.classList.add("a")});if(t==="d")pgAdD();else if(t==="u")pgAdU();else if(t==="t")pgAdT()}\n'
+'function pgAdD(){var e=document.getElementById("adC");e.innerHTML=\'<div class="ld"><div class="sp"></div><p>加载中...</p></div>\';api("GET","/admin/stats").then(function(s){var h=\'<div class="st" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))"><div class="c"><div class="n">\'+s.users+\'</div><div class="l">用户数</div></div><div class="c"><div class="n">\'+s.threads+\'</div><div class="l">帖子数</div></div><div class="c"><div class="n">\'+s.posts+\'</div><div class="l">回复数</div></div></div><div class="card"><h4 style="margin-bottom:12px">最近注册</h4>\';if(s.recentUsers&&s.recentUsers.length>0){h+=\'<table class="tbl"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>时间</th></tr></thead><tbody>\';s.recentUsers.forEach(function(u){h+=\'<tr><td>\'+u.id+\'</td><td>\'+esc(u.username)+\'</td><td>\'+(u.role==="admin"?\'<span class="badge">管理员</span>\':"用户")+\'</td><td>\'+u.created_at+\'</td></tr>\'});h+=\'</tbody></table>\'}h+=\'</div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+'function pgAdU(){var e=document.getElementById("adC");e.innerHTML=\'<div class="ld"><div class="sp"></div><p>加载中...</p></div>\';api("GET","/admin/users").then(function(us){var h=\'<div class="card"><h4 style="margin-bottom:12px"> 用户管理</h4><table class="tbl"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>时间</th><th>操作</th></tr></thead><tbody>\';us.forEach(function(u){h+=\'<tr><td>\'+u.id+\'</td><td>\'+esc(u.username)+\'</td><td>\'+(u.role==="admin"?\'<span class="badge">管理员</span>\':"用户")+\'</td><td>\'+u.created_at+\'</td><td>\';if(u.id!==CU.id){h+=\'<button class="btn btn-sm" onclick="setR(\'+u.id+\',\\\'admin\\\')\'">设管理员</button> <button class="btn btn-d btn-sm" onclick="delU(\'+u.id+\')"> 删除</button>\'}else{h+=\'<span style="color:#6b7280">当前用户</span>\'}h+=\'</td></tr>\'});h+=\'</tbody></table></div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+'function setR(uid,role){api("POST","/admin/set-role",{user_id:uid,role:role}).then(function(){to("角色已更新");pgAdU()}).catch(function(e){})}\n'
+'function delU(uid){if(!confirm("确定删除？"))return;api("DELETE","/admin/users/"+uid).then(function(){to("用户已删除");pgAdU()}).catch(function(e){})}\n'
+'function pgAdT(){var e=document.getElementById("adC");e.innerHTML=\'<div class="ld"><div class="sp"></div><p>加载中...</p></div>\';api("GET","/threads?page=1").then(function(d){var h=\'<div class="card"><h4 style="margin-bottom:12px"> 帖子管理</h4><table class="tbl"><thead><tr><th>ID</th><th>标题</th><th>作者</th><th>回复</th><th>时间</th><th>操作</th></tr></thead><tbody>\';d.threads.forEach(function(t){h+=\'<tr><td>\'+t.id+\'</td><td>\'+esc(t.title).substring(0,30)+\'</td><td>\'+esc(t.username)+\'</td><td>\'+(t.reply_count||0)+\'</td><td>\'+ago(t.created_at)+\'</td><td><button class="btn btn-d btn-sm" onclick="adDTh(\'+t.id+\')"> 删除</button></td></tr>\'});h+=\'</tbody></table></div>\';e.innerHTML=h}).catch(function(){e.innerHTML="<p>加载失败</p>"})}\n'
+'function adDTh(id){if(!confirm("确定删除？"))return;api("DELETE","/threads/"+id).then(function(){to("已删除");pgAdT()}).catch(function(e){})}\n'
+'upd();rt();})();\n</script>\n</body>\n</html>';
}

// ─── 主入口 ───
export default {
  async fetch(request, env, ctx) {
    try { await initDB(env); } catch (e) {}
    var url = new URL(request.url), path = url.pathname;

    if (path.startsWith('/api/')) {
      var p = path.replace('/api', ''), m = request.method, body = {};
      if (['POST','PUT','DELETE'].includes(m)) try { body = await request.json(); } catch (e) {}

      if (p === '/auth/register' && m === 'POST') return apiReg(env, body);
      if (p === '/auth/login' && m === 'POST') return apiLog(env, body);
      if (p === '/auth/logout' && m === 'POST') return apiOut(env, request);
      if (p === '/me' && m === 'GET') return apiMe(env, request);
      if (p === '/categories' && m === 'GET') return json(env, request);
      if (p === '/threads' && m === 'GET') return apiThr(env, request);
      if (p.match(/^\/threads\/\d+$/) && m === 'GET') return apiThrD(env, p.split('/')[2]);
      if (p === '/threads' && m === 'POST') return apiCThr(env, request, body);
      if (p.match(/^\/threads\/\d+$/) && m === 'DELETE') return apiDTh(env, request, p.split('/')[2]);
      if (p === '/posts' && m === 'POST') return apiCPo(env, request, body);
      if (p.match(/^\/posts\/\d+$/) && m === 'DELETE') return apiDPo(env, request, p.split('/')[2]);
      if (p === '/admin/stats' && m === 'GET') return apiAS(env, request);
      if (p === '/admin/users' && m === 'GET') return apiAU(env, request);
      if (p === '/admin/set-role' && m === 'POST') return apiASR(env, request, body);
      if (p.match(/^\/admin\/users\/\d+$/) && m === 'DELETE') return apiAD(env, request, p.split('/')[3]);
      return json({ error: 'Not Found' }, 404);
    }

    try { return new Response(htmlPage(await getU(env, request)), { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); }
    catch (e) { return new Response('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>NW Forum</title></head><body style="display:flex;justify-content:center;align-items:center;min-height:100vh;font-family:sans-serif;color:#6b7280"><p>加载失败，请刷新。如持续出现请检查 D1 绑定。</p></body></html>', { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); }
  }
};
