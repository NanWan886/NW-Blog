export default {
  async fetch(request, env, ctx) {
    const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <title>站点开发中</title>
      <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{height:100vh;display:flex;align-items:center;justify-content:center;background:#111;color:#fff;font-size:22px;font-family:system-ui}
        .box{text-align:center}
      </style>
    </head>
    <body>
      <div class="box">
        <h1>🚧 站点开发中ing.....</h1>
        <p style="margin-top:16px;opacity:0.7">敬请期待，正在加紧开发</p>
      </div>
    </body>
    </html>
    `
    return new Response(html, {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache' // 禁止浏览器缓存页面
      },
    });
  },
};