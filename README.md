# Yet Another Permission Middleware for Koa

A role based acl middleware for Koa

# ACL Define

acl.js

```js
const Rule = { role: 'baduser', action: 'reject' };

module.exports = [
  Rule,
  {
    path: '^/apple/',
    role: 'auser',
    methods: ['get', 'post', 'delete', 'patch'],
    action: 'accept'
  },
  {
    path: '^/banana/',
    role: 'buser',
    action: 'accept'
  }
  //default reject for others
];
```
## Rule format

* path    - request path, can be regex, case insensitive, optional, match all paths when not present
* role    - request user role, to whom the rule will be performed, case sensitive, optional, match all when not present
* methods - request methods, array, case insensitive, optional, match all when not present
* action  - accept/reject, case sensitive, required

# Usage in Koa

server.js

```js
const Koa = require('koa');
const Jwt = require('koa-jwt');
const Permission = require('yapmk'):
const acls = requre('./acls');

const app = new Koa();

app.use(Jwt({ secret: 'my jwt secret' }));

const options = {
  getRoles: ctx => ctx.state.auth.roleNames,
  acls
};

app.use(Permission(options));

app.use((ctx, next) => {
  ctx.body = "OK";
})

app.listen(3000);
```

## Option format

* getRole   - function, get user roles as array, required
* acls      - array, the acl rule array

## The middleware comes with [koa-unless](https://github.com/Foxandxss/koa-unless) integrated, to exclude role checking for some conditions

```js
app.use(Permission(options).unless({ path: [/^\/public\//] }));
```

# Prerequisites

A user authenticating method may be need to provide valid user roles, [koa-jwt](https://github.com/koajs/jwt) can be used here.

# License

  MIT
