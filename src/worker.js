export default {
  async fetch(request, env, ctx) {
    return new Response('开发中ing.....', {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  },
};
