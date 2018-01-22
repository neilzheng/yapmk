const unless = require('koa-unless');

const arrayHas = (arr, item) => {
  for (let i = 0; i < arr.length; i += 1) {
    if (item === arr[i]) return true;
  }
  return false;
};

const normalizeAcl = acl => acl.map((rule) => {
  if (!rule.action) throw new TypeError('action must be set in ACL rule');

  return {
    path: rule.path ? new RegExp(rule.path.toLowerCase()) : undefined,
    role: rule.role,
    methods: rule.methods ? rule.methods.map(value => value.toLowerCase()) : undefined,
    action: rule.action,
    match(path, method, roleNames) {
      if (this.path) {
        if (!this.path.test(path)) return false;
      }

      if (this.methods &&
          !arrayHas(this.methods, method)) {
        return false;
      }

      if (this.role) {
        for (let i = 0; i < roleNames.length; i += 1) {
          if (arrayHas(roleNames, this.role)) return true;
        }
        return false;
      }

      return true;
    }
  };
});

module.exports = (opts) => {
  const { getRoles, acl } = opts;
  if (typeof getRoles !== 'function') throw new TypeError('getRoles must be a function');
  if (!acl || !Array.isArray(acl)) throw new TypeError('acl must be an nonempty array');
  const realAcl = normalizeAcl(acl);

  const middleware = (ctx, next) => {
    const { path, method } = ctx;
    const roleNames = getRoles(ctx);

    if (arrayHas(roleNames, 'admin')) return next();

    for (let i = 0; i < realAcl.length; i += 1) {
      const rule = realAcl[i];
      if (rule.match(path.toLowerCase(), method.toLowerCase(), roleNames)) {
        if (rule.action === 'accept') return next();
        break;
      }
    }

    ctx.throw(403);
    return false;
  };

  middleware.unless = unless;
  return middleware;
};
