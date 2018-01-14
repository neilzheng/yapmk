const Koa = require('koa');

module.exports = (roles) => {
  const app = new Koa();
  app.use((ctx, next) => {
    const state = { ...ctx.state };
    state.auth = { roleNames: roles };
    ctx.state = state;
    return next();
  });
  return app;
};
