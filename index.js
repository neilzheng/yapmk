const unless = require('koa-unless');

const arrayHas = (arr, item) => {
  for (let i = 0; i < arr.length; i += 1) {
    if (item === arr[i]) return true;
  }
  return false;
};

const normalizeAcls = acls => acls.map((acl) => {
  if (!acl.action) throw new TypeError('action must be set in ACL rule');

  return {
    path: acl.path ? acl.path.toLowerCase() : undefined,
    role: acl.role,
    methods: acl.methods ? acl.methods.map(value => value.toLowerCase()) : undefined,
    action: acl.action,
    match(path, method, roleNames) {
      if (this.path) {
        const pathRE = new RegExp(this.path);
        if (!pathRE.test(path)) return false;
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
  const { getRoles, acls } = opts;
  if (typeof getRoles !== 'function') throw new TypeError('getRoles must be a function');
  if (!acls || !Array.isArray(acls)) throw new TypeError('acls must be an nonempty array');
  const realAcls = normalizeAcls(acls);

  const middleware = (ctx, next) => {
    const { path, method } = ctx;
    const roleNames = getRoles(ctx);

    if (arrayHas(roleNames, 'admin')) return next();

    for (let i = 0; i < realAcls.length; i += 1) {
      const rule = realAcls[i];
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
