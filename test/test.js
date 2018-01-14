const request = require('supertest');

const ACL = require('../');
const createApp = require('./server');

const getRoles = ctx => ctx.state.auth.roleNames;

describe('reject all', () => {
  describe('user access', () => {
    const acls = [
      {
        action: 'reject'
      }
    ];
    const app = createApp(['user']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 403 for /apple/', (done) => {
      req.get('/apple/')
        .expect(403)
        .end(done);
    });

    it('should response 403 for /banana/', (done) => {
      req.get('/banana/')
        .expect(403)
        .end(done);
    });

    server.close();
  });
});

describe('admin rules all', () => {
  describe('admin access', () => {
    const acls = [
      {
        action: 'reject'
      }
    ];
    const app = createApp(['user', 'admin']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    it('should response 200 for /banana/', (done) => {
      req.get('/banana/')
        .expect(200)
        .end(done);
    });

    server.close();
  });
});

describe('reject unless public', () => {
  describe('user access', () => {
    const acls = [
      {
        action: 'reject'
      }
    ];
    const app = createApp(['user']);
    app.use(ACL({ getRoles, acls }).unless({ path: [/^\/public\//] }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 403 for /apple/', (done) => {
      req.get('/apple/')
        .expect(403)
        .end(done);
    });

    it('should response 200 for /public/', (done) => {
      req.get('/public/')
        .expect(200)
        .end(done);
    });

    server.close();
  });
});

describe('accept all', () => {
  describe('user access', () => {
    const acls = [
      {
        action: 'accept'
      }
    ];
    const app = createApp(['user']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    it('should response 200 for /banana/', (done) => {
      req.get('/banana/')
        .expect(200)
        .end(done);
    });

    server.close();
  });
});

describe('auser can access apple, buser can access banana', () => {
  describe('auser access', () => {
    const acls = [
      {
        path: '^/apple/',
        role: 'auser',
        action: 'accept'
      },
      {
        path: '^/banana/',
        role: 'buser',
        action: 'accept'
      }
    ];
    const app = createApp(['auser']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    it('should response 200 for /apple/big', (done) => {
      req.get('/apple/big')
        .expect(200)
        .end(done);
    });

    it('should response 403 for /banana/', (done) => {
      req.get('/banana/')
        .expect(403)
        .end(done);
    });

    it('should response 403 for /banana/big', (done) => {
      req.get('/banana/big')
        .expect(403)
        .end(done);
    });

    server.close();
  });

  describe('buser access', () => {
    const acls = [
      {
        path: '^/apple/',
        role: 'auser',
        action: 'accept'
      },
      {
        path: '^/banana/',
        role: 'buser',
        action: 'accept'
      }
    ];
    const app = createApp(['buser']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 403 for /apple/', (done) => {
      req.get('/apple/')
        .expect(403)
        .end(done);
    });

    it('should response 403 for /apple/big', (done) => {
      req.get('/apple/big')
        .expect(403)
        .end(done);
    });

    it('should response 200 for /banana/', (done) => {
      req.get('/banana/')
        .expect(200)
        .end(done);
    }); 

    it('should response 200 for /banana/big', (done) => {
      req.get('/banana/big')
        .expect(200)
        .end(done);
    });

    server.close();
  });
});

describe('user can get, manager can post', () => {
  describe('user access', () => {
    const acls = [
      {
        path: '^/apple/',
        role: 'user',
        methods: ['get'],
        action: 'accept'
      },
      {
        path: '^/apple/',
        role: 'manager',
        methods: ['post'],
        action: 'accept'
      }
    ];
    const app = createApp(['user']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for get /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    it('should response 403 for post /apple/', (done) => {
      req.post('/apple/', { data: 'test' })
        .expect(403)
        .end(done);
    });

    server.close();
  });

  describe('manager access', () => {
    const acls = [
      {
        path: '^/apple/',
        role: 'user',
        methods: ['get'],
        action: 'accept'
      },
      {
        path: '^/apple/',
        role: 'manager',
        methods: ['post'],
        action: 'accept'
      }
    ];
    const app = createApp(['user', 'manager']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for get /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    it('should response 200 for post /apple/', (done) => {
      req.post('/apple/', { data: 'test' })
        .expect(200)
        .end(done);
    });

    server.close();
  });
});

describe('block bad user', () => {
  describe('user access', () => {
    const acls = [
      {
        role: 'baduser',
        action: 'reject'
      },
      {
        action: 'accept'
      }
    ];
    const app = createApp(['user']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 200 for get /apple/', (done) => {
      req.get('/apple/')
        .expect(200)
        .end(done);
    });

    server.close();
  });

  describe('bad user access', () => {
    const acls = [
      {
        role: 'baduser',
        action: 'reject'
      },
      {
        action: 'accept'
      }
    ];
    const app = createApp(['baduser']);
    app.use(ACL({ getRoles, acls }));
    app.use((ctx, next) => {
      ctx.body = 'OK';
      return next();
    });
    const server = app.listen();
    const req = request(server);

    it('should response 403 for get /apple/', (done) => {
      req.get('/apple/')
        .expect(403)
        .end(done);
    });

    server.close();
  });
});
