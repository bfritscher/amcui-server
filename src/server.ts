import * as Sentry from '@sentry/node';
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    tracesSampleRate: 1.0,
  });
}

import fs from 'fs-extra';
import StreamSplitter from 'stream-splitter';
import cors from 'cors';
import {createServer} from 'http';
import express from 'express';
import {Server} from 'socket.io';
import errorHandler from 'errorhandler';
import sqlite3 from 'sqlite3';
import path from 'path';
import jwt from 'jsonwebtoken';
import {authorize} from '@thream/socketio-jwt';
import {expressjwt, Request as JWTRequest} from 'express-jwt';
import bcrypt from 'bcrypt';
import {createClient, type RedisClientType} from 'redis';
import xml2js from 'xml2js';
import {mkdirp} from 'mkdirp';
import ACL from 'acl2';
import multer from 'multer';
import tmp from 'tmp';
import childProcess from 'child_process';
import {simpleGit} from 'simple-git';
import archiver from 'archiver';
import slug from 'slug';
import sizeOf from 'image-size';
import {fileURLToPath} from 'url';
import {dirname} from 'path';
import {authenticator} from 'otplib';
import QRCode from 'qrcode';
import {Factor, Fido2Lib} from 'fido2-lib';
import * as base64buffer from 'base64-arraybuffer';
import {WebSocketServer} from 'ws';

import {URL} from 'url';
import ywsUtils from 'y-websocket/bin/utils';
import {ywsRedisPersistence} from './ywspersistence.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

slug.defaults.mode = 'rfc3986';

function str2ab(str: string) {
  const enc = new TextEncoder();
  return enc.encode(str);
}

if (!process.env.JWT_SECRET) {
  /* c8 ignore next */
  throw new Error('JWT_SECRET env variable must be set!');
}

// This allows TypeScript to detect our global value
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: User;
    }
    interface User {
      username: string;
    }
  }
}

const app = express();
Sentry.setupExpressErrorHandler(app);

const APP_FOLDER = path.resolve(__dirname, '../src/');
const PROJECTS_FOLDER = path.resolve(__dirname, '../projects/');
const TEMPLATES_FOLDER = path.resolve(__dirname, '../templates/');

const redisClient = (await createClient({socket: {port: 6379, host: 'redis'}})
  .on('error', (err) => {
    console.log('Redis error ' + err);
    Sentry.captureException(err);
  })
  .connect()) as RedisClientType;
const acl = new ACL(new ACL.redisBackend({redis: redisClient, prefix: 'acl'}));

const f2l = new Fido2Lib({
  rpName: 'AMCUI',
});

async function addProjectAcl(project: string, username: string | undefined) {
  if (!username) return;
  //role, resource, permission
  await acl.allow(project, '/project/' + project, 'admin');
  //user, role
  await acl.addUserRoles(username, project);
}

const corsOptions: cors.CorsOptions = {
  origin: true,
  credentials: true,
  exposedHeaders: [
    'Accept-Ranges',
    'Content-Encoding',
    'Content-Length',
    'Content-Range',
  ],
};

app.use(cors(corsOptions));

const httpServer = createServer(app);
const ws = new Server(httpServer, {cors: corsOptions});

ws.use(
  authorize({
    secret: process.env.JWT_SECRET,
  })
);

// setup y-websocket
ywsRedisPersistence(redisClient, 'exam2', 'ws/');

const wss = new WebSocketServer({noServer: true});

wss.on('connection', ywsUtils.setupWSConnection);

httpServer.on('upgrade', (request, socket, head) => {
  // You may check auth of request here..
  // Call `wss.HandleUpgrade` *after* you checked whether the client has access
  // (e.g. by checking cookies, or url parameters).
  // See https://github.com/websockets/ws#client-authentication
  // Parse the request URL
  const requestUrl = new URL(
    request.url || '',
    `wss://${request.headers.host}`
  );
  if (requestUrl.pathname.startsWith('/ws')) {
    // Get the access_token parameter
    const accessToken = requestUrl.searchParams.get('access_token');
    // TODO: implement auth here?
    console.log('TODO check', accessToken);
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
  }
});

const uploadMiddleware = multer({dest: '/tmp/amcui-uploads/'});

async function userSaveVisit(username: string, projectName: string) {
  await redisClient.ZADD('user:' + username + ':recent', {
    score: new Date().getTime(),
    value: projectName,
  });
  await redisClient.ZREMRANGEBYRANK('user:' + username + ':recent', 0, -11);
}

ws.on('connection', (socket) => {
  //this socket is authenticated, we are good to handle more events from it.
  const username: string = socket.decodedToken.username;

  socket.on('listen', async (project: string) => {
    const hasRole = await acl.hasRole(username, project);
    if (!hasRole) {
      socket.disconnect(true);
    } else {
      userSaveVisit(username, project);
      socket.join(project + '-notifications');
    }
  });
});

const env = process.env.NODE_ENV || 'development';
if (env === 'development') {
  sqlite3.verbose();
} else if (env === 'production') {
  app.use(express.static(__dirname + '/public'));
}

app.use(express.urlencoded({extended: true}));
app.use(express.json({limit: '50mb'}));
app.use(function (req, _res, next) {
  if (req.is('text/*')) {
    req.body = '';
    req.setEncoding('utf8');
    req.on('data', function (chunk) {
      req.body += chunk;
    });
    req.on('end', next);
  } else {
    next();
  }
});

const secureJwt = expressjwt({
  secret: process.env.JWT_SECRET,
  algorithms: ['HS256'],
  getToken: function fromHeaderOrQuerystring(req) {
    if (
      req.headers.authorization &&
      req.headers.authorization.split(' ')[0] === 'Bearer'
    ) {
      return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
      return String(req.query.token);
    }
    return;
  },
});

// map auth to user because of migration from 6 to 8 of express-jwt
const secure = (
  req: JWTRequest,
  res: express.Response,
  next: express.NextFunction
) => {
  secureJwt(req, res, (err) => {
    if (err) {
      return next(err);
    }
    if (req.auth) {
      req.user = req.auth as any;
    }
    next();
  });
};

//secure /project with auth api
app.use('/project', secure);
app.use('/admin', secure);
app.use('/profile', secure);

const aclProject: express.RequestHandler = acl.middleware(
  2,
  (req) => {
    return (req as express.Request)?.user?.username as any;
  },
  'admin'
);

const aclAdmin: express.RequestHandler = acl.middleware(
  1,
  (req) => {
    return (req as express.Request)?.user?.username as any;
  },
  'admin'
);

//TODO check types with db
interface DbParams {
  $threshold?: number;
  $student?: string;
  $page?: string;
  $copy?: string;
  $manual?: number;
  $type?: string;
  $id_a?: string;
  $id_b?: string;
}

function database(
  req: express.Request,
  res: express.Response,
  callback: (
    dbReady: (
      method: keyof sqlite3.Database,
      query: string,
      params: DbParams | ((rows: any[]) => void),
      success?: (rows: any[] | any) => void
    ) => void
  ) => void
): void {
  const project = req.params.project;
  const db = new sqlite3.Database(
    PROJECTS_FOLDER + '/' + project + '/data/capture.sqlite',
    (err) => {
      if (err) {
        console.log(err);
        res.status(500).end(JSON.stringify(err));
        return;
      }
      db.exec(
        "ATTACH DATABASE '" +
          PROJECTS_FOLDER +
          '/' +
          project +
          "/data/layout.sqlite' AS layout",
        () => {
          db.exec(
            "ATTACH DATABASE '" +
              PROJECTS_FOLDER +
              '/' +
              project +
              "/data/association.sqlite' AS assoc",
            () => {
              db.exec(
                "ATTACH DATABASE '" +
                  PROJECTS_FOLDER +
                  '/' +
                  project +
                  "/data/scoring.sqlite' AS scoring",
                () => {
                  const dbHandled = (
                    method: keyof sqlite3.Database,
                    query: string,
                    params: DbParams | ((rows: any[]) => void),
                    success?: (rows: any[] | any) => void
                  ): void => {
                    const internalCallback = (
                      err: Error | null,
                      rows: any[]
                    ): void => {
                      if (err) {
                        console.log(err);
                        res.status(500).end(JSON.stringify(err));
                        return;
                      }
                      if (success) {
                        success(rows);
                      } else {
                        if (typeof params === 'function') {
                          params(rows);
                        }
                      }
                    };

                    if (success) {
                      // @ts-ignore
                      db[method](query, params, internalCallback);
                    } else {
                      // @ts-ignore
                      db[method](query, internalCallback);
                    }
                  };
                  callback(dbHandled);
                }
              );
            }
          );
        }
      );
    }
  );
}

function projectOptions(
  project: string,
  callback: (err: Error | null, result: any) => void
): void {
  const filename = path.resolve(PROJECTS_FOLDER, project + '/options.xml');
  fs.readFile(filename, 'utf-8', function (err, data) {
    if (err) {
      callback(err, null);
    } else {
      xml2js.parseString(data, {explicitArray: false}, (err, result) => {
        // auto-upgrade old options files
        if (result.projetAMC) {
          result.project = result.projetAMC;
          delete result.projetAMC;
        }
        callback(err, result);
      });
    }
  });
}

function projectThreshold(
  project: string,
  callback: (err: Error | null, threshold: number) => void
): void {
  projectOptions(project, (_err, result) => {
    let threshold = 0.5;
    if (result.project.seuil && !isNaN(result.project.seuil)) {
      threshold = parseFloat(result.project.seuil);
    }
    callback(null, threshold);
  });
}

function amcCommande(
  res: express.Response | null,
  cwd: string,
  project: string,
  msg: string,
  params: string[],
  callback?: ((log: string) => void) | null,
  error?: (() => void) | null
): void {
  ws.to(project + '-notifications').emit('log', {
    command: params[0],
    msg: msg,
    action: 'start',
    params: params,
  });
  const amc = childProcess.spawn('auto-multiple-choice', params, {
    cwd: cwd,
  });

  let log = '';
  let errorlog = '';

  //send complete lines
  const splitter = amc.stdout.pipe(StreamSplitter('\n'));
  splitter.encoding = 'utf8';
  splitter.on('token', function (token: string) {
    log += token + '\n';
    ws.to(project + '-notifications').emit('log', {
      command: params[0],
      msg: msg,
      action: 'log',
      data: token,
    });
  });

  amc.stderr.on('data', (data) => {
    errorlog += data;
    ws.to(project + '-notifications').emit('log', {
      command: params[0],
      msg: msg,
      action: 'err',
      data: data.toString(),
    });
  });
  amc.on('close', async (code) => {
    ws.to(project + '-notifications').emit('log', {
      command: params[0],
      msg: msg,
      action: 'end',
      code: code,
    });
    if (code === 0) {
      if (callback) {
        callback(log);
      }
    } else {
      await redisClient.HSET('project:' + project + ':status', 'locked', '0');
      if (error) {
        error();
      }
      const debug = {
        log: log,
        command: params,
        errorlog: errorlog,
        error: code,
      };
      if (res) {
        res.json(debug);
      }
    }
  });
}

app.get('/', (_req, res) => {
  res.json({
    name: 'AMCUI API SERVER',
    sha: process.env.COMMIT_SHA,
  });
});

app.get('/templates', async (_req, res) => {
  const files = await fs.readdir(TEMPLATES_FOLDER, {withFileTypes: true});
  res.json(
    files.filter((dirent) => dirent.isDirectory()).map((dirent) => dirent.name)
  );
});

app.get('/debug-sentry', () => {
  throw new Error('Sentry express test');
});

await acl.allow('admin', '/admin', 'admin');
if (process.env.ADMIN_USER) {
  addProjectAcl('admin', process.env.ADMIN_USER);
}

function countStudentsCSV(project: string): Promise<number> {
  const filename = path.resolve(PROJECTS_FOLDER, project + '/students.csv');
  return new Promise((resolve) => {
    fs.readFile(filename, (err, data) => {
      if (err) {
        resolve(-1);
      } else {
        resolve(data.toString('utf8').split('\n').length - 1);
      }
    });
  });
}

// TODO migrate master to main?
async function countGitCommits(
  project: string,
  branch = 'master'
): Promise<number> {
  if (!fs.existsSync(PROJECTS_FOLDER + '/' + project + '/.git')) {
    return -1;
  }
  try {
    const g = simpleGit(PROJECTS_FOLDER + '/' + project);
    const data = await g.raw(['rev-list', '--count', branch]);
    return Number(data.trim());
  } catch (err) {
    if (branch === 'master') {
      return countGitCommits(project, 'main');
    }
    return -1;
  }
}

app.get('/admin/stats', aclAdmin, async (_req, res) => {
  const stats = {users: {} as any, projects: {} as any};
  const roles = new Set<string>();
  const users = new Set<string>();
  const exams = await redisClient.KEYS('exam:*');
  exams.forEach((name: string) => {
    roles.add(name.split(':')[1]);
  });
  const exams2 = await redisClient.KEYS('exam2:*');
  exams2.forEach((name: string) => {
    roles.add(name.split(':')[1]);
  });
  const projects = await redisClient.KEYS('project:*');
  projects.forEach((name: string) => {
    roles.add(name.split(':')[1]);
  });
  const aclProjects = await redisClient.SMEMBERS('acl_meta@roles');
  aclProjects.forEach((name: string) => {
    roles.add(name);
  });

  const dbUsers = await redisClient.KEYS('user:*');
  dbUsers.forEach((name: string) => {
    users.add(name.split(':')[1]);
  });

  const aclUsers = await redisClient.SMEMBERS('acl_meta@users');
  aclUsers.forEach((name: string) => {
    users.add(name);
  });

  await Promise.all(
    [...users].map(async (user: string) => {
      stats.users[user] = await acl.userRoles(user);
    })
  );

  await Promise.all(
    [...roles].map(async (project: string) => {
      const p = {
        students: undefined as undefined | number,
        commits: undefined as undefined | number,
        v2: exams2.includes('exam2:' + project),
      };
      stats.projects[project] = p;
      p.commits = await countGitCommits(project);
      p.students = await countStudentsCSV(project);
    })
  );

  res.json(stats);
});

app.get('/admin/du', aclAdmin, (_req, res) => {
  const size = childProcess.spawn('du', ['-k', '-d 2'], {
    cwd: PROJECTS_FOLDER,
  });
  size.stdout.setEncoding('utf8');
  const projects: any = {};
  const re = /(\d+)[\t ]+\.\/([^/]*)\/?(.*)/;
  const splitter = size.stdout.pipe(StreamSplitter('\n'));
  splitter.encoding = 'utf8';
  splitter.on('token', function (data: string) {
    const entry = re.exec(data.trim());
    if (entry === null) {
      return;
    }
    if (!projects.hasOwnProperty(entry[2])) {
      projects[entry[2]] = {total: 0, folders: []};
    }
    if (entry[3] === '') {
      projects[entry[2]].total = Number(entry[1]);
    } else {
      const folder: any = {};
      folder[entry[3]] = Number(entry[1]);
      projects[entry[2]].folders.push(folder);
    }
  });

  size.on('exit', () => {
    Object.keys(projects).forEach((k) => {
      const p = projects[k];
      const sum = p.folders.reduce((total: number, f: any) => {
        return total + f[Object.keys(f)[0]];
      }, 0);
      p.folders.push({'.': p.total - sum});
    });
    res.json(projects);
  });
});

app.post('/admin/import', aclAdmin, (req, res) => {
  // Warning, does not check if project folder is valid
  addProjectAcl(req.body.project, req.user?.username);
  res.sendStatus(200);
});

app.post('/admin/addtoproject', aclAdmin, async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  await acl.addUserRoles(req.user.username, req.body.project);
  const msg = `ADMIN: ${req.user.username} added himself to ${req.body.project}`;
  Sentry.captureMessage(msg);
  res.sendStatus(200);
});

app.post('/admin/removefromproject', aclAdmin, async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  await acl.removeUserRoles(req.user.username, req.body.project);
  const msg = `ADMIN: ${req.user.username} removed himself from ${req.body.project}`;
  Sentry.captureMessage(msg);
  res.sendStatus(200);
});

app.post('/admin/user/:username/removemfa', aclAdmin, async (req, res) => {
  const reply = await redisClient.GET('user:' + req.params.username);
  if (reply) {
    const user = JSON.parse(reply);
    user.authenticators = [];
    await redisClient.SET('user:' + user.username, JSON.stringify(user));
    res.sendStatus(200);
  } else {
    res.status(404).send('user not found');
  }
});

app.post('/admin/user/:username/changepassword', aclAdmin, async (req, res) => {
  const reply = await redisClient.GET('user:' + req.params.username);
  if (reply) {
    const user = JSON.parse(reply);
    user.password = bcrypt.hashSync(req.body.newPassword, 10);
    await redisClient.SET('user:' + user.username, JSON.stringify(user));
    res.sendStatus(200);
  } else {
    res.status(404).send('user not found');
  }
});

app.post('/admin/project/:project/delete', aclAdmin, (req, res) => {
  deleteProject(req.params.project, (err) => {
    if (err) {
      res.sendStatus(404);
    } else {
      res.sendStatus(200);
    }
  });
});

app.post('/admin/project/:project/gitgc', aclAdmin, async (req, res) => {
  const g = simpleGit(PROJECTS_FOLDER + '/' + req.params.project);
  const data = await g.raw(['gc', '--aggressive']);
  res.json(data);
});

app.post('/admin/user/:username/delete', aclAdmin, async (req, res) => {
  const username = req.params.username;
  const roles = await acl.userRoles(username);
  roles.forEach(async (project) => {
    await acl.removeUserRoles(username, project);
  });
  redisClient.DEL('user:' + username);
  redisClient.DEL('user:' + username + ':recent');
  redisClient.SREM('acl_meta@users', username);
  res.sendStatus(200);
});

/*
ZONE_FRAME=>1,
ZONE_NAME=>2,
ZONE_DIGIT=>3, //top of the page id
ZONE_BOX=>4,
*/
/* corner
(1=TL, 2=TR, 3=BR, 4=BL)
*/

/* type
POSITION_BOX=>1,
POSITION_MEASURE=>2,
*/

/*
version > 1.2.1 feature seuil-up not supported

 */

/* Project API */
app.post('/login', async (req, res) => {
  if (!req.body.username) {
    return res.sendStatus(400);
  }
  const username = req.body.username.toLowerCase();
  const sendToken = (user: any): void => {
    try {
      delete user.password;
      user.authenticators = user.authenticators
        ? user.authenticators.map(
            ({label, type}: {label: string; type: string}) => {
              return {
                label,
                type,
              };
            }
          )
        : [];
      const token = jwt.sign(user, process.env.JWT_SECRET || '', {
        expiresIn: '6h',
      });
      res.json({token: token});
    } catch (e) {
      console.log('login', e, user);
      res.status(500).send(e);
    }
  };
  const userData = await redisClient.GET('user:' + username);

  if (!userData) {
    // create Account
    const password = bcrypt.hashSync(req.body.password, 10);
    const newUser = {username: username, password: password};
    await redisClient.SET('user:' + newUser.username, JSON.stringify(newUser));
    sendToken(newUser);
  } else {
    const user = JSON.parse(userData);
    if (bcrypt.compareSync(req.body.password, user.password)) {
      // check mfa
      if (user.authenticators && user.authenticators.length > 0) {
        if (
          req.body.authenticator &&
          req.body.authenticator.type === 'authenticator' &&
          req.body.authenticator.token
        ) {
          // validate token test all
          if (
            user.authenticators
              .filter((c: {type: string}) => c.type === 'authenticator')
              .some((config: {secret: string}) => {
                return authenticator.verify({
                  token: req.body.authenticator.token,
                  secret: config.secret,
                });
              })
          ) {
            sendToken(user);
          } else {
            res.status(401).send('Wrong token');
          }
        } else if (
          req.body.authenticator &&
          req.body.authenticator.type === 'fido2'
        ) {
          // validate fido2
          const logResponse = req.body.authenticator.response;
          const credListFiltered = user.authenticators.filter(
            (x: {credentialId: string}) => x.credentialId == logResponse.rawId
          );

          if (!credListFiltered.length)
            return res.status(404).send('Authenticator does not exist');
          const thisCred = credListFiltered.pop();

          logResponse.rawId = base64buffer.decode(logResponse.rawId);
          logResponse.response.authenticatorData = base64buffer.decode(
            logResponse.response.authenticatorData
          );

          const assertionExpectations = {
            challenge: Fido2inMemoryChallenges[user.username],
            origin: process.env.FRONTEND_DOMAIN
              ? `https://${process.env.FRONTEND_DOMAIN}`
              : 'http://localhost:8080',
            factor: 'either' as Factor, // TODO config?
            publicKey: thisCred.publicKey,
            prevCounter: thisCred.counter,
            userHandle: thisCred.credentialId,
          };

          f2l
            .assertionResult(logResponse, assertionExpectations)
            .then(async (logResult) => {
              thisCred.counter = logResult.authnrData.get('counter');
              delete Fido2inMemoryChallenges[user.username];
              await redisClient.SET(
                'user:' + user.username,
                JSON.stringify(user)
              );
              sendToken(user);
            })
            .catch((err) => {
              res.status(401).send(err.message);
            });
        } else {
          // request mfa
          const authenticators = {
            authenticator: user.authenticators
              .filter(
                (config: {type: string}) => config.type === 'authenticator'
              )
              .map(({label, type}: {label: string; type: string}) => {
                return {
                  label,
                  type,
                };
              }),
            fido2: {}, // TODO add fido request challenge
          };
          const filteredFido2 = user.authenticators.filter(
            (config: {type: string}) => config.type === 'fido2'
          );
          if (filteredFido2.length > 0) {
            const authnOptions: any = await f2l.assertionOptions();
            authnOptions.challenge = base64buffer.encode(
              authnOptions.challenge
            );
            authnOptions.allowCredentials = filteredFido2.map(
              (config: {credentialId: string}) => {
                return {id: config.credentialId, type: 'public-key'};
              }
            );
            Fido2inMemoryChallenges[user.username] = authnOptions.challenge;
            authenticators.fido2 = authnOptions;
          }
          res.send(authenticators);
        }
      } else {
        // only password login
        sendToken(user);
      }
    } else {
      res.status(401).send('Wrong user or password');
    }
  }
});

app.post('/profile/addAuthenticator', async (req, res) => {
  const userData = await redisClient.GET('user:' + req.user?.username);
  if (!userData) {
    return res.sendStatus(401);
  }
  const user = JSON.parse(userData);
  if (!bcrypt.compareSync(req.body.password, user.password)) {
    return res.status(500).send('Wrong password');
  }
  if (!user.authenticators) {
    user.authenticators = [];
  }
  if (
    user.authenticators
      .filter((c: {type: string}) => c.type === 'authenticator')
      .map((c: {label: string}) => c.label)
      .includes(req.body.label)
  ) {
    return res.status(500).send('name already exists');
  }
  const authenticatorConfig = {
    type: 'authenticator',
    label: req.body.label,
    secret: authenticator.generateSecret(),
  };
  user.authenticators.push(authenticatorConfig);
  await redisClient.SET('user:' + user.username, JSON.stringify(user));
  // TODO config
  const service = 'AMCUI Server';
  const otpauthUrl = authenticator.keyuri(
    user.username,
    service,
    authenticatorConfig.secret
  );
  QRCode.toDataURL(otpauthUrl)
    .then((qrCodeDataUrl) => {
      res.send({
        otpauthUrl,
        qrCodeDataUrl,
      });
    })
    .catch(() => {
      res.send({
        otpauthUrl,
      });
    });
});

app.post('/profile/removeMFA', async (req, res) => {
  const userData = await redisClient.GET('user:' + req.user?.username);
  if (!userData) {
    return res.sendStatus(401);
  }
  const user = JSON.parse(userData);
  if (!bcrypt.compareSync(req.body.password, user.password)) {
    return res.status(500).send('Wrong user or password');
  }
  user.authenticators = user.authenticators
    ? user.authenticators.filter(
        (authConfig: {type: string; label: string}) =>
          !(
            authConfig.type === req.body.type &&
            authConfig.label === req.body.label
          )
      )
    : [];
  await redisClient.SET('user:' + user.username, JSON.stringify(user));
  res.sendStatus(200);
});

app.post('/changePassword', async (req, res) => {
  if (req.body.password && req.body.username && req.body.newPassword) {
    const username = req.body.username.toLowerCase();
    const reply = await redisClient.GET('user:' + username);
    if (reply) {
      const user = JSON.parse(reply);
      if (bcrypt.compareSync(req.body.password, user.password)) {
        user.password = bcrypt.hashSync(req.body.newPassword, 10);
        await redisClient.SET('user:' + user.username, JSON.stringify(user));
        res.sendStatus(200);
      } else {
        res.status(404).send('Wrong user or password');
      }
    } else {
      res.status(404).send('Wrong user or password');
    }
  } else {
    res.status(404).send('Wrong user or password');
  }
});

const Fido2inMemoryChallenges = {} as {[key: string]: string};

app.get('/profile/addFido2', async (req, res) => {
  const userData = await redisClient.GET('user:' + req.user?.username);
  if (!userData) {
    return res.sendStatus(401);
  }
  const user = JSON.parse(userData);
  f2l
    .attestationOptions()
    .then((regOptions: any) => {
      regOptions.user = {
        id: base64buffer.encode(str2ab(user.username)),
        name: user.username,
        displayName: user.username,
      };
      regOptions.challenge = base64buffer.encode(regOptions.challenge);
      Fido2inMemoryChallenges[user.username] = regOptions.challenge;
      res.send(regOptions);
    })
    .catch(() => {
      res.sendStatus(500);
    });
});

app.post('/profile/addFido2', async (req, res) => {
  const userData = await redisClient.GET('user:' + req.user?.username);
  if (!userData) {
    return res.sendStatus(401);
  }
  const user = JSON.parse(userData);
  if (!bcrypt.compareSync(req.body.password, user.password)) {
    return res.status(500).send('Wrong password');
  }
  if (!user.authenticators) {
    user.authenticators = [];
  }
  if (
    user.authenticators
      .filter((c: {type: string}) => c.type === 'fido2')
      .map((c: {label: string}) => c.label)
      .includes(req.body.label)
  ) {
    return res.status(500).send('name already exists');
  }

  const regResponse = req.body.response;
  regResponse.rawId = base64buffer.decode(regResponse.rawId);

  const attestationExpectations = {
    challenge: Fido2inMemoryChallenges[user.username],
    origin: 'http://localhost:8080', // TODO config
    factor: 'either' as Factor, // TODO config
  };

  f2l
    .attestationResult(regResponse, attestationExpectations)
    .then(async (regResult) => {
      const authnrData = regResult.authnrData;
      user.authenticators.push({
        type: 'fido2',
        label: req.body.label,
        counter: authnrData.get('counter'),
        credentialId: base64buffer.encode(authnrData.get('credId')),
        publicKey: authnrData.get('credentialPublicKeyPem'),
      });
      delete Fido2inMemoryChallenges[user.username];
      await redisClient.SET('user:' + user.username, JSON.stringify(user));
      res.sendStatus(200);
    })
    .catch((err) => {
      console.log(err);
      res.status(500).send(err.message);
    });
});

app.get('/project/list', async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const roles = await acl.userRoles(req.user.username);
  const projects: any[] = [];
  roles.forEach(async (role) => {
    const status = await redisClient.HGETALL('project:' + role + ':status');
    const users = await acl.roleUsers(role);
    projects.push({
      project: role,
      status: status,
      users: users,
    });
    if (projects.length === roles.length) {
      res.json(projects);
    }
  });
});

app.get('/project/recent', async (req, res) => {
  try {
    const response = await redisClient.ZRANGE(
      'user:' + req.user?.username + ':recent',
      0,
      -1,
      {REV: true}
    );
    res.json(response);
  } catch (e) {
    res.json([]);
  }
});

function createProject(
  projectName: string,
  username: string,
  success: (project: string) => void,
  error: () => void
): void {
  // create project
  const project = slug(projectName);
  if (project === 'admin') {
    return error();
  }
  const root = path.resolve(PROJECTS_FOLDER, project);
  if (!fs.existsSync(root)) {
    mkdirp.sync(root + '/cr/corrections/jpg');
    mkdirp.sync(root + '/cr/corrections/pdf');
    mkdirp.sync(root + '/cr/zooms');
    mkdirp.sync(root + '/cr/diagnostic');
    mkdirp.sync(root + '/data');
    mkdirp.sync(root + '/scans');
    mkdirp.sync(root + '/exports');
    mkdirp.sync(root + '/out');
    mkdirp.sync(root + '/pdf');
    mkdirp.sync(root + '/src/graphics');
    mkdirp.sync(root + '/src/codes');
    //copy default option file
    fs.copySync(
      path.resolve(APP_FOLDER, 'assets/options.xml'),
      root + '/options.xml'
    );
    fs.copySync(
      path.resolve(APP_FOLDER, 'assets/students.csv'),
      root + '/students.csv'
    );
    fs.copySync(
      path.resolve(APP_FOLDER, 'assets/gitignore.template'),
      root + '/.gitignore'
    );

    addProjectAcl(project, username);
    //create association db other are created on print
    amcCommande(
      null,
      PROJECTS_FOLDER + '/' + project,
      project,
      'create association db',
      [
        'association-auto',
        '--data',
        PROJECTS_FOLDER + '/' + project + '/data',
        '--notes-id',
        'etu',
        '--liste',
        PROJECTS_FOLDER + '/' + project + '/students.csv',
        '--liste-key',
        'id',
      ],
      null
    );

    if (success) {
      success(project);
    }
  } else {
    if (error) {
      error();
    }
  }
}

function ignoreGitError() {}

async function commitGit(
  project: string,
  username: string,
  message: string
): Promise<void> {
  const g = simpleGit(PROJECTS_FOLDER + '/' + project);
  await g.init().catch(ignoreGitError);
  await g.raw(['add', '--all', '.']).catch((err: Error | null) => {
    if (err) {
      console.log('add', err);
      Sentry.captureException(err);
    }
  });
  await g
    .raw([
      'commit',
      '--author=' + username + ' <' + username + '@amcui.ig.he-arc.ch>',
      '-m',
      message,
    ])
    .catch((err: Error | null) => {
      if (err) {
        console.log('commit', err);
        Sentry.captureException(err);
      }
    });
}

app.post('/project/create', (req, res) => {
  if (!req.user) return res.sendStatus(403);
  createProject(
    req.body.project,
    req.user.username,
    (project) => {
      res.send(project);
    },
    () => {
      res.status(403).send('Project already exists!');
    }
  );
});

app.get('/project/:project/options', aclProject, (req, res) => {
  projectOptions(req.params.project, async (_err, result) => {
    const users = await acl.roleUsers(req.params.project);
    const status = await redisClient.HGETALL(
      'project:' + req.params.project + ':status'
    );
    res.json({
      options: result ? result.project : {},
      users: users,
      status: status,
    });
  });
});

app.post('/project/:project/options', aclProject, (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const filename = path.resolve(
    PROJECTS_FOLDER,
    req.params.project + '/options.xml'
  );
  const builder = new xml2js.Builder();
  const xml = builder.buildObject({project: req.body.options});
  fs.writeFile(filename, xml, function (err) {
    if (err) {
      res.sendStatus(500);
    } else {
      ws.to(req.params.project + '-notifications').emit(
        'update:options',
        req.body.options
      );
      commitGit(req.params.project, req.user?.username || '', 'options');
      res.sendStatus(200);
    }
  });
});

app.get('/project/:project/dbversions', aclProject, (req, res) => {
  database(req, res, (db) => {
    db(
      'get',
      `SELECT (SELECT value FROM capture_variables WHERE name = 'version') capture,
              (SELECT value FROM layout_variables WHERE name = 'version') layout,
              (SELECT value FROM association_variables WHERE name = 'version') association,
              (SELECT value FROM scoring_variables WHERE name = 'version') scoring`,
      (rows) => {
        res.json(rows);
      }
    );
  });
});

app.post('/project/:project/copy/template', aclProject, (req, res) => {
  const TEMPLATE_FOLDER = TEMPLATES_FOLDER + '/' + req.body.template;
  fs.copy(
    TEMPLATE_FOLDER + '/src',
    PROJECTS_FOLDER + '/' + req.params.project + '/src',
    () => {
      res.sendFile(TEMPLATE_FOLDER + '/source.tex');
    }
  );
});

app.post('/project/:project/copy/project', aclProject, (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const src = req.params.project;
  const dest = req.body.project.toLowerCase();
  createProject(
    dest,
    req.user.username,
    () => {
      fs.copy(
        PROJECTS_FOLDER + '/' + src + '/src',
        PROJECTS_FOLDER + '/' + dest + '/src',
        async (err) => {
          if (err) {
            res.status(500).send('Failed to copy src files.');
          } else {
            fs.copy(
              PROJECTS_FOLDER + '/' + src + '/data.json',
              PROJECTS_FOLDER + '/' + dest + '/data.json',
              async (err) => {
                if (err) {
                  res.status(500).send('Failed to copy src files.');
                } else {
                  res.sendStatus(200);
                }
              }
            );
          }
        }
      );
    },
    () => {
      res.status(403).send('Project already exists!');
    }
  );
});

//TODO: handle only graphics or codes needed?
app.post('/project/:project/copy/graphics', aclProject, async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const src = req.params.project;
  const dest = req.body.project.toLowerCase();
  const hasRole = await acl.hasRole(req.user.username, dest);
  if (hasRole && src !== dest) {
    fs.copy(
      PROJECTS_FOLDER + '/' + src + '/src/graphics',
      PROJECTS_FOLDER + '/' + dest + '/src/graphics',
      (err) => {
        if (err) {
          res.status(500).send('Failed to copy src files.');
        } else {
          res.sendStatus(200);
        }
      }
    );
  } else {
    res.sendStatus(403);
  }
});
//TODO: refactor?
app.post('/project/:project/copy/codes', aclProject, async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const src = req.params.project;
  const dest = req.body.project.toLowerCase();
  const hasRole = await acl.hasRole(req.user.username, dest);
  if (hasRole && src !== dest) {
    fs.copy(
      PROJECTS_FOLDER + '/' + src + '/src/codes',
      PROJECTS_FOLDER + '/' + dest + '/src/codes',
      (err) => {
        if (err) {
          res.status(500).send('Failed to copy src files.');
        } else {
          res.sendStatus(200);
        }
      }
    );
  } else {
    res.sendStatus(403);
  }
});

app.post('/project/:project/add', aclProject, async (req, res) => {
  await acl.addUserRoles(req.body.username, req.params.project);
  res.sendStatus(200);
});

app.post('/project/:project/remove', aclProject, async (req, res) => {
  //cannot remove self
  if (req.body.username === req.user?.username) {
    res.sendStatus(500);
  } else {
    await acl.removeUserRoles(req.body.username, req.params.project);
    res.sendStatus(200);
  }
});

app.post('/project/:project/rename', aclProject, (req, res) => {
  const project = req.params.project;
  const newProject = slug(req.body.name);
  if (newProject.length === 0 || newProject.indexOf('.') === 0) {
    return res.sendStatus(404);
  }
  //check that destination does not exists

  const newPath = PROJECTS_FOLDER + '/' + newProject;
  if (fs.existsSync(newPath)) {
    return res.sendStatus(403);
  }

  fs.rename(PROJECTS_FOLDER + '/' + project, newPath, async (err) => {
    if (err) {
      console.log(err);
      return res.status(500).send(err);
    }
    if (await redisClient.EXISTS('exam:' + project) > 0) {
      await redisClient.RENAMENX('exam:' + project, 'exam:' + newProject);
    }
    if (await redisClient.EXISTS('exam2:' + project) > 0) {
      await redisClient.RENAMENX('exam2:' + project, 'exam2:' + newProject);
    }
    await acl.allow(newProject, '/project/' + newProject, 'admin');
    const users = await acl.roleUsers(project);
    users.forEach(async (username: string) => {
      await acl.removeUserRoles(username, project);
      await acl.addUserRoles(username, newProject);
      await redisClient.ZREM('user:' + username + ':recent', project);
    });
    const keys = await redisClient.KEYS('project:' + project + ':*');
    keys.forEach(async (key) => {
      const entries = key.split(':');
      await redisClient.RENAMENX(
        key,
        'project:' + newProject + ':' + entries[2]
      );
    });
    await acl.removeAllow(project, '/project/' + project, 'admin');
    await acl.removeRole(project);
    await acl.removeResource(project);
    res.send(newProject);
  });
});

async function deleteProject(
  project: string,
  callback: (err: boolean) => void
) {
  if (project.length === 0 || project.indexOf('.') === 0) {
    callback(true);
  }
  if (project === 'admin') {
    return callback(true);
  }
  const users = await acl.roleUsers(project);
  users.forEach(async (username: string) => {
    await acl.removeUserRoles(username, project);
    await redisClient.ZREM('user:' + username + ':recent', project);
  });
  await acl.removeAllow(project, '/project/' + project, 'admin');
  await acl.removeRole(project);
  await acl.removeResource(project);
  await redisClient.DEL(['exam:' + project, 'exam2:' + project]);
  const keys = await redisClient.KEYS('project:' + project + ':*');
  keys.forEach((key) => {
    redisClient.DEL(key);
  });
  fs.remove(PROJECTS_FOLDER + '/' + project, (err) => {
    if (err) {
      callback(true);
    } else {
      callback(false);
    }
  });
}

app.post('/project/:project/delete', aclProject, (req, res) => {
  deleteProject(req.params.project, (err) => {
    if (err) {
      res.sendStatus(404);
    } else {
      res.sendStatus(200);
    }
  });
});

/*
TODO ?
archive project
zip correction/scans...
delete/recreate git
flag as archive
*/

app.get('/project/:project/gitlogs', aclProject, async (req, res) => {
  // TODO? use cI when git version supports it
  try {
    const g = simpleGit(PROJECTS_FOLDER + '/' + req.params.project);
    const data = await g.raw([
      'log',
      '--walk-reflogs',
      '--pretty=format:%H%+gs%+an%+ci',
    ]);
    const logs = [];
    const json = data.split('\n');
    let i = 0;
    while (i < json.length) {
      const msg = json[i + 1];
      const idx = msg.indexOf(':');
      const log = {
        sha: json[i],
        type: msg.substring(0, idx),
        msg: msg.substring(idx + 2),
        username: json[i + 2],
        date: new Date(json[i + 3]),
      };
      logs.push(log);
      i += 4;
    }
    res.json(logs);
  } catch (err) {
    console.log(err);
    res.status(500).send(err);
  }
});

app.post('/project/:project/revert', aclProject, (req, res) => {
  const g = simpleGit(PROJECTS_FOLDER + '/' + req.params.project);
  g.raw(['reset', '--hard', req.body.sha], (err: Error | null) => {
    if (err) {
      Sentry.captureException(err);
      res.status(500).send(err);
    }
    const json = path.resolve(
      PROJECTS_FOLDER,
      req.params.project + '/data.json'
    );
    res.send(fs.readFileSync(json));
  });
});

app.get('/project/:project/zip', aclProject, (req, res) => {
  const zip = archiver('zip');
  res.on('close', function () {
    return res.end();
  });
  res.attachment(req.params.project + '.zip');
  zip.pipe(res);
  zip.directory(PROJECTS_FOLDER + '/' + req.params.project, req.params.project);
  zip.finalize();
});

app.get('/project/:project/static/:file*', aclProject, (req, res) => {
  let file = req.params.file;
  if (req.params.hasOwnProperty(0)) {
    file += req.params[0];
  }
  res.sendFile(
    PROJECTS_FOLDER + '/' + req.params.project + '/' + file,
    (err) => {
      if (err && file.split('.').splice(-1)[0] === 'jpg') {
        res.sendFile(APP_FOLDER + '/assets/image_not_found.jpg');
      } else if (err) {
        res.end('NOT_FOUND');
      }
    }
  );
});

function makeThumb(
  project: string,
  filename: string,
  id: string,
  callback?: null | ((code: number | null) => void)
): void {
  const GRAPHICS_FOLDER = PROJECTS_FOLDER + '/' + project + '/src/graphics/';
  const convert = childProcess.spawn(
    'convert',
    [
      '-trim',
      '+repage',
      '-background',
      'white',
      '-alpha',
      'remove',
      '-density',
      '120',
      filename + '[0]',
      id + '_thumb.jpg',
    ],
    {
      cwd: GRAPHICS_FOLDER,
    }
  );
  convert.on('exit', (code) => {
    if (callback) {
      callback(code);
    }
  });
}

/* EDIT */
app.post(
  '/project/:project/upload/graphics',
  aclProject,
  uploadMiddleware.single('file'),
  (req, res) => {
    if (!req.file) return res.sendStatus(500);
    const GRAPHICS_FOLDER =
      PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
    //keep extension
    const filename =
      req.body.id + '.' + req.file.originalname.split('.').splice(-1)[0];
    fs.copySync(req.file.path, GRAPHICS_FOLDER + filename);
    // don't forget to delete all req.files when done
    fs.unlinkSync(req.file.path);
    makeThumb(req.params.project, filename, req.body.id, (code: any) => {
      if (code === 0) {
        res.sendStatus(200);
      } else {
        res.sendStatus(500);
      }
    });
  }
);

app.get('/project/:project/graphics/sync', aclProject, (req, res) => {
  const GRAPHICS_FOLDER =
    PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
  const allFiles = fs.readdirSync(GRAPHICS_FOLDER);
  //remove thumbs from list
  const files = allFiles.filter((filename) => {
    return !filename.match(/(.*)_thumb.jpg/);
  });
  //get files without thumb
  files
    .filter((filename) => {
      return (
        allFiles.indexOf(filename.replace(/(.*)\..*?$/, '$1_thumb.jpg')) === -1
      );
    })
    .forEach((filename) => {
      makeThumb(
        req.params.project,
        filename,
        filename.replace(/(.*)\..*?$/, '$1'),
        null
      );
    });
  res.json(files);
});

app.post('/project/:project/graphics/delete', aclProject, (req, res) => {
  const GRAPHICS_FOLDER =
    PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
  try {
    fs.unlinkSync(
      GRAPHICS_FOLDER +
        req.body.id +
        '.' +
        req.body.filename.split('.').splice(-1)[0]
    );
    fs.unlinkSync(GRAPHICS_FOLDER + req.body.id + '_thumb.jpg');
    res.sendStatus(200);
  } catch (e) {
    res.sendStatus(500);
  }
});

function saveSourceFilesSync(project: string, body: any): void {
  const OUT_FOLDER = PROJECTS_FOLDER + '/' + project + '/out';
  fs.readdirSync(OUT_FOLDER).forEach((item) => {
    fs.unlinkSync(OUT_FOLDER + '/' + item);
  });

  const json = path.resolve(PROJECTS_FOLDER, project + '/data.json');
  fs.writeFileSync(json, body.json);

  const source = path.resolve(PROJECTS_FOLDER, project + '/source.tex');
  fs.writeFileSync(source, body.source);

  const questionsDefinition = path.resolve(
    PROJECTS_FOLDER,
    project + '/questions_definition.tex'
  );
  fs.writeFileSync(questionsDefinition, body.questions_definition);

  const questionsLayout = path.resolve(
    PROJECTS_FOLDER,
    project + '/questions_layout.tex'
  );
  fs.writeFileSync(questionsLayout, body.questions_layout);

  for (const id in body.codes) {
    if (body.codes.hasOwnProperty(id)) {
      const file = path.resolve(PROJECTS_FOLDER, project + '/src/codes/' + id);
      fs.writeFileSync(file, body.codes[id].content);
    }
  }
}

app.post('/project/:project/preview', aclProject, async (req, res) => {
  const keyStatus = 'project:' + req.params.project + ':status';
  const keyQueue = 'project:' + req.params.project + ':previewqueue';
  const project = req.params.project;

  async function compilePreviewEnd() {
    await redisClient.HSET(keyStatus, 'preview', '0');
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    compilePreview();
  }

  function compilePreviewSuccess(): void {
    commitGit(project, req.user?.username || '', 'preview');
    compilePreviewEnd();
  }

  async function compilePreview() {
    const status = await redisClient.HGETALL(keyStatus);
    if (status && (status.locked > '0' || status.preview > '0')) {
      // wait
      setTimeout(compilePreview, 1000);
      return;
    }
    const data = await redisClient.GET(keyQueue);
    if (data) {
      await redisClient.DEL(keyQueue);
      const body = JSON.parse(data);
      await redisClient.HSET(keyStatus, 'preview', '1');
      //compile
      saveSourceFilesSync(project, body);
      amcCommande(
        null,
        PROJECTS_FOLDER + '/' + project,
        project,
        'preview',
        [
          'prepare',
          '--with',
          'pdflatex',
          '--filter',
          'latex',
          '--out-corrige',
          'out/out.pdf',
          '--mode',
          'k',
          '--n-copies',
          '1',
          'source.tex',
          '--latex-stdout',
        ],
        compilePreviewSuccess,
        compilePreviewEnd
      );
    }
  }
  //replace next compile data
  await redisClient.SET(keyQueue, JSON.stringify(req.body));
  compilePreview();
  res.sendStatus(200);
});

app.get('/project/:project/reset/lock', aclProject, async (req, res) => {
  await redisClient.HSET('project:' + req.params.project + ':status', {
    locked: 0,
    preview: 0,
  });
  res.end();
});

/* PRINT */
app.post('/project/:project/print', aclProject, async (req, res) => {
  const locked = await redisClient.HGET(
    'project:' + req.params.project + ':status',
    'locked'
  );
  if (locked === '1') {
    return res.status(409).end('ALREADY PRINTING!');
  }

  await redisClient.HSET('project:' + req.params.project + ':status', {
    locked: 1,
    printed: '',
  });
  const PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
  const project = req.params.project;

  saveSourceFilesSync(req.params.project, req.body);

  fs.readdirSync(PROJECT_FOLDER + 'pdf/').forEach((item) => {
    fs.unlinkSync(PROJECT_FOLDER + 'pdf/' + item);
  });

  res.sendStatus(200);

  ws.to(project + '-notifications').emit('print', {action: 'start'});

  projectOptions(req.params.project, (_err, result) => {
    //sujet.pdf, catalog.pdf, calage.xy
    amcCommande(
      null,
      PROJECT_FOLDER,
      project,
      'generating pdf',
      [
        'prepare',
        '--with',
        'pdflatex',
        '--filter',
        'latex',
        '--mode',
        's[c]',
        '--n-copies',
        result.project.nombre_copies,
        'source.tex',
        '--prefix',
        PROJECT_FOLDER,
        '--latex-stdout',
        '--data',
        PROJECT_FOLDER + 'data',
      ],
      () => {
        //corrige.pdf for all series
        amcCommande(
          null,
          PROJECT_FOLDER,
          project,
          'generating answers pdf',
          [
            'prepare',
            '--with',
            'pdflatex',
            '--filter',
            'latex',
            '--mode',
            'k',
            '--n-copies',
            result.project.nombre_copies,
            'source.tex',
            '--prefix',
            PROJECT_FOLDER,
            '--latex-stdout',
          ],
          () => {
            //create capture and scoring db
            amcCommande(
              null,
              PROJECT_FOLDER,
              project,
              'computing scoring data',
              [
                'prepare',
                '--mode',
                'b',
                '--n-copies',
                result.project.nombre_copies,
                'source.tex',
                '--prefix',
                PROJECT_FOLDER,
                '--data',
                PROJECT_FOLDER + 'data',
                '--latex-stdout',
              ],
              () => {
                //create layout
                amcCommande(
                  null,
                  PROJECT_FOLDER,
                  project,
                  'calculating layout',
                  [
                    'meptex',
                    '--src',
                    PROJECT_FOLDER + 'calage.xy',
                    '--data',
                    PROJECT_FOLDER + 'data',
                    '--progression-id',
                    'MEP',
                    '--progression',
                    '1',
                  ],
                  () => {
                    // print
                    const params = [
                      'imprime',
                      '--methode',
                      'file',
                      '--output',
                      PROJECT_FOLDER + 'pdf/sheet-%e.pdf',
                      '--sujet',
                      'sujet.pdf',
                      '--data',
                      PROJECT_FOLDER + 'data',
                      '--progression-id',
                      'impression',
                      '--progression',
                      '1',
                    ];
                    if (result.project.split === '1') {
                      params.push('--split');
                    }
                    amcCommande(
                      null,
                      PROJECT_FOLDER,
                      project,
                      'splitting pdf',
                      params,
                      async () => {
                        const pdfs = fs
                          .readdirSync(PROJECT_FOLDER + 'pdf/')
                          .filter((item) => {
                            return item.indexOf('.pdf') > 0;
                          });
                        commitGit(project, req.user?.username || '', 'print');
                        await redisClient.HSET(
                          'project:' + req.params.project + ':status',
                          {
                            locked: 0,
                            printed: new Date().getTime(),
                          }
                        );
                        ws.to(project + '-notifications').emit('print', {
                          action: 'end',
                          pdfs: pdfs,
                        });
                      }
                    );
                  }
                );
              }
            );
          }
        );
      }
    );
  });
});

app.get('/project/:project/zip/pdf', aclProject, (req, res) => {
  const zip = archiver('zip');
  res.on('close', function () {
    return res.end();
  });
  res.attachment(req.params.project + '.zip');
  zip.pipe(res);
  zip.directory(PROJECTS_FOLDER + '/' + req.params.project + '/pdf', 'sujets');
  zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/catalog.pdf', {
    name: 'catalog.pdf',
  });
  zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/corrige.pdf', {
    name: 'corrige.pdf',
  });
  zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/calage.xy', {
    name: 'calage.xy',
  });
  zip.file(APP_FOLDER + '/assets/print.bat', {name: 'print.bat.txt'});
  zip.finalize();
});

/* validation

$delta=0.1
# * {'NO_BOX} is a pointer on an array containing all the student
#   numbers for which there is no box to be filled in the subject
#
# * {'NO_NAME'} is a pointer on an array containing all the student
#   numbers for which there is no name field
#
# * {'SEVERAL_NAMES'} is a pointer on an array containing all the student
#   numbers for which there is more than one name field
'DEFECT_NO_BOX'=>
       {'sql'=>"SELECT student FROM (SELECT student FROM ".$self->table("page")
	." GROUP BY student) AS list"
	." WHERE student>0 AND"
	."   NOT EXISTS(SELECT * FROM ".$self->table("box")." AS local WHERE role=1 AND"
	."              local.student=list.student)"},
       'DEFECT_NO_NAME'=>
       {'sql'=>"SELECT student FROM (SELECT student FROM ".$self->table("page")
	." GROUP BY student) AS list"
	." WHERE student>0 AND"
	."   NOT EXISTS(SELECT * FROM ".$self->table("namefield")." AS local"
	."              WHERE local.student=list.student)"},
       'DEFECT_SEVERAL_NAMES'=>
       {'sql'=>"SELECT student FROM (SELECT student,COUNT(*) AS n FROM "
	.$self->table("namefield")." GROUP BY student) AS counts WHERE n>1"},
# check_positions($delta) checks if all pages has the same positions
# for marks and binary digits boxes. If this is the case (this SHOULD
# allways be the case), check_positions returns undef. If not,
# check_positions returns a hashref
# {student_a=>S1,page_a=>P1,student_b=>S2,page_b=>P2} showing an
# example for which (S1,P1) has not the same positions as (S2,P2)
# (with difference over $delta for at least one coordinate).
'checkPosDigits'=>
       {'sql'=>"SELECT a.student AS student_a,b.student AS student_b,"
	."         a.page AS page_a, b.page AS page_b,* FROM"
	." (SELECT * FROM"
	."   (SELECT * FROM ".$self->table("digit")
	."    ORDER BY student DESC,page DESC)"
	."  GROUP BY numberid,digitid) AS a,"
	."  ".$self->table("digit")." AS b"
	." ON a.digitid=b.digitid AND a.numberid=b.numberid"
	."    AND (abs(a.xmin-b.xmin)>? OR abs(a.xmax-b.xmax)>?"
	."         OR abs(a.ymin-b.ymin)>? OR abs(a.ymax-b.ymax)>?)"
	." LIMIT 1"},
       'checkPosMarks'=>
       {'sql'=>"SELECT a.student AS student_a,b.student AS student_b,"
	."         a.page AS page_a, b.page AS page_b,* FROM"
	." (SELECT * FROM"
	."   (SELECT * FROM ".$self->table("mark")
	."    ORDER BY student DESC,page DESC)"
	."  GROUP BY corner) AS a,"
	."  ".$self->table("mark")." AS b"
	." ON a.corner=b.corner"
	."    AND (abs(a.x-b.x)>? OR abs(a.y-b.y)>?)"
	." LIMIT 1"},
*/

/* CAPTURE*/

app.post(
  '/project/:project/upload',
  aclProject,
  uploadMiddleware.single('file'),
  (req, res) => {
    if (!req.file) return res.sendStatus(500);
    const filename = req.file.originalname;
    const PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
    const project = req.params.project;
    fs.copySync(
      req.file.path,
      path.resolve(PROJECTS_FOLDER, req.params.project, 'scans/', filename)
    );
    // don't forget to delete all req.files when done
    fs.unlinkSync(req.file.path);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    tmp.file((_err, path, _fd, _cleanup) => {
      fs.writeFileSync(path, 'scans/' + filename);
      // need to call getimage with file to get path of extracted files...
      amcCommande(
        res,
        PROJECT_FOLDER,
        project,
        'extracting images',
        [
          'getimages',
          '--progression-id',
          'getimages',
          '--progression',
          '1',
          '--vector-density',
          '250',
          '--orientation',
          'portrait',
          '--copy-to', // using copy-to to generate correct absolute url (needed for creating correct %PROJECT in DB)
          PROJECT_FOLDER + 'scans',
          '--list',
          path,
        ],
        (logImages) => {
          projectOptions(req.params.project, (_err, result) => {
            const params = [
              'analyse',
              '--tol-marque',
              '0.2,0.2',
              '--prop',
              '0.8',
              '--bw-threshold',
              '0.6',
              '--progression-id',
              'analyse',
              '--progression',
              '1',
              '--projet',
              PROJECT_FOLDER,
              '--cr',
              PROJECT_FOLDER + 'cr',
              '--data',
              PROJECT_FOLDER + 'data',
              '--liste-fichiers',
              path,
            ];
            if (result.project.auto_capture_mode === '1') {
              params.push('--multiple');
              // In multiple mode we must process one file after another in the order we receive them in order to not get mixups
              // force AMC:Queue to 1 process
              params.push('--n-procs');
              params.push('1');
            } else {
              params.push('--n-procs');
              params.push('0');
            }
            amcCommande(
              res,
              PROJECT_FOLDER,
              project,
              'analysing image',
              params,
              async (logAnalyse) => {
                await redisClient.HSET(
                  'project:' + project + ':status',
                  'scanned',
                  new Date().getTime().toString()
                );
                res.json({
                  logImages: logImages,
                  logAnalyse: logAnalyse,
                });
              }
            );
          });
        }
      );
    });
  }
);

app.get('/project/:project/missing', aclProject, (req, res) => {
  database(req, res, (db) => {
    //TODO in future check that role=1 version>1.2.1
    const query =
      'SELECT a.student as student, a.page as page, a.copy as copy, ok.page IS NULL as missing ' +
      'FROM (SELECT enter.student, enter.page, p.copy FROM ( ' +
      '    SELECT student, page ' +
      '    FROM layout_zone WHERE zone="__n"' +
      '    UNION ' +
      '    SELECT student, page ' +
      '    FROM layout_box) enter, ' +
      '    (SELECT student, copy FROM capture_page GROUP BY student, copy) p' +
      '  WHERE p.student = enter.student) a ' +
      'LEFT JOIN capture_page ok ON a.student = ok.student AND a.page = ok.page AND ok.copy = a.copy ' +
      'ORDER BY student, copy, page';

    db('all', query, (rows) => {
      const seenTotal: any[] = [];
      const seenMissing: any[] = [];
      if (!rows) {
        rows = [];
      }
      const results = rows.reduce(
        (result, page) => {
          const id = page.student + '_' + page.copy;
          if (seenTotal.indexOf(id) < 0) {
            result.complete += 1;
            seenTotal.push(id);
          }
          if (page.missing === 1) {
            result.missing.push(page);
            if (seenMissing.indexOf(id) < 0) {
              result.complete -= 1;
              result.incomplete += 1;
              seenMissing.push(id);
            }
          }
          return result;
        },
        {complete: 0, incomplete: 0, missing: []}
      );

      const query2 = 'SELECT * FROM capture_failed';
      db('all', query2, (rows) => {
        results.failed = rows;
        res.json(results);
      });
    });
  });
});

app.get('/project/:project/capture', aclProject, (req, res) => {
  projectThreshold(req.params.project, (_err, threshold) => {
    database(req, res, (db) => {
      const query =
        "SELECT p.student || '/' || p.page || ':' || p.copy as id, p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, " +
        '(SELECT ROUND(10* COALESCE(($threshold - MIN(ABS(1.0*black/total - $threshold)))/ $threshold, 0), 1) ' +
        'FROM capture_zone WHERE student=p.student AND page=p.page AND copy=p.copy AND type=4) s ' +
        'FROM capture_page p ORDER BY p.student, p.page, p.copy';

      db('all', query, {$threshold: threshold}, (rows) => {
        res.json(rows || []);
      });
    });
  });
});

app.get(
  '/project/:project/capture/:student/:page::copy',
  aclProject,
  (req, res) => {
    database(req, res, (db) => {
      const query =
        'SELECT c.src, c.student, c.page, c.copy, c.timestamp_auto, c.timestamp_manual, c.a, c.b, c.c, c.d, c.e, c.f, ' +
        'c.mse, c.layout_image, l.dpi, l.width as originalwidth, l.width, l.height as originalheight, l.height FROM capture_page c JOIN layout_page l ON c.student = l.student AND c.page = l.page WHERE c.student=$student AND c.page=$page AND c.copy=$copy';
      db(
        'get',
        query,
        {
          $student: req.params.student,
          $page: req.params.page,
          $copy: req.params.copy,
        },
        (row) => {
          if (row) {
            sizeOf(
              PROJECTS_FOLDER +
                '/' +
                req.params.project +
                '/cr/' +
                row.layout_image,
              function (_err, dimensions) {
                row.ratiox = 1;
                row.ratioy = 1;
                if (dimensions && dimensions.width && dimensions.height) {
                  row.ratiox = row.width / dimensions.width;
                  row.ratioy = row.height / dimensions.height;
                  row.width = dimensions.width;
                  row.height = dimensions.height;
                }
                res.json(row);
              }
            );
          } else {
            res.sendStatus(404);
          }
        }
      );
    });
  }
);

app.post('/project/:project/capture/setauto', aclProject, (req, res) => {
  database(req, res, (db) => {
    let query =
      'UPDATE capture_page SET timestamp_annotate=0, timestamp_manual=0 WHERE student=$student AND page=$page AND copy=$copy';
    db(
      'run',
      query,
      {
        $student: req.body.student,
        $page: req.body.page,
        $copy: req.body.copy,
      },
      () => {
        query =
          'UPDATE capture_zone SET manual=-1 WHERE student=$student AND page=$page AND copy=$copy';
        db(
          'run',
          query,
          {
            $student: req.body.student,
            $page: req.body.page,
            $copy: req.body.copy,
          },
          async () => {
            await redisClient.HSET(
              'project:' + req.params.project + ':status',
              'scanned',
              new Date().getTime().toString()
            );
            res.sendStatus(200);
          }
        );
      }
    );
  });
});

/* TODO: support insert for fully manual pages */
app.post('/project/:project/capture/setmanual', aclProject, (req, res) => {
  database(req, res, (db) => {
    let query =
      "UPDATE capture_page SET timestamp_annotate=0, timestamp_manual=strftime('%s','now') WHERE student=$student AND page=$page AND copy=$copy";
    db(
      'run',
      query,
      {
        $student: req.body.student,
        $page: req.body.page,
        $copy: req.body.copy,
      },
      () => {
        query =
          'UPDATE capture_zone SET manual=$manual WHERE student=$student AND page=$page AND copy=$copy AND type=$type AND id_a=$id_a AND id_b=$id_b';
        db(
          'run',
          query,
          {
            $manual: req.body.manual,
            $student: req.body.student,
            $page: req.body.page,
            $copy: req.body.copy,
            $type: req.body.type,
            // eslint-disable-next-line @typescript-eslint/camelcase
            $id_a: req.body.id_a,
            // eslint-disable-next-line @typescript-eslint/camelcase
            $id_b: req.body.id_b,
          },
          async () => {
            await redisClient.HSET(
              'project:' + req.params.project + ':status',
              'scanned',
              new Date().getTime().toString()
            );
            res.sendStatus(200);
          }
        );
      }
    );
  });
});

app.post('/project/:project/capture/delete', aclProject, (req, res) => {
  /*
	1) get image files generated, and remove them
    scan file, layout image, in cr directory, annotated scan, zooms
    */
  database(req, res, (db) => {
    const query =
      "SELECT replace(src, '%PROJET/', '') as path FROM capture_page " +
      'WHERE student=$student AND page=$page AND copy=$copy ' +
      'UNION ' +
      "SELECT 'cr/' || layout_image FROM capture_page " +
      'WHERE student=$student AND page=$page AND copy=$copy ' +
      'UNION ' +
      "SELECT 'cr/corrections/jpg/' || annotated FROM capture_page " +
      'WHERE student=$student AND page=$page AND copy=$copy ' +
      'UNION ' +
      "SELECT 'cr/' || image FROM capture_zone " +
      'WHERE student=$student AND page=$page AND copy=$copy AND image IS NOT NULL';
    db(
      'all',
      query,
      {
        $student: req.body.student,
        $page: req.body.page,
        $copy: req.body.copy,
      },
      (rows) => {
        rows.forEach((row: any) => {
          fs.unlink(
            PROJECTS_FOLDER + '/' + req.params.project + '/' + row.path,
            (err) => {
              console.log('unlick', err);
            }
          );
        });
        // 2) remove data from database
        db(
          'run',
          'DELETE FROM capture_position WHERE zoneid IN (SELECT zoneid FROM capture_zone WHERE student=$student AND page=$page AND copy=$copy)',
          {
            $student: req.body.student,
            $page: req.body.page,
            $copy: req.body.copy,
          },
          () => {
            db(
              'run',
              'DELETE FROM capture_zone WHERE student=$student AND page=$page AND copy=$copy',
              {
                $student: req.body.student,
                $page: req.body.page,
                $copy: req.body.copy,
              },
              () => {
                db(
                  'run',
                  'DELETE FROM capture_page WHERE student=$student AND page=$page AND copy=$copy',
                  {
                    $student: req.body.student,
                    $page: req.body.page,
                    $copy: req.body.copy,
                  },
                  () => {
                    db(
                      'run',
                      'DELETE FROM scoring_score WHERE student=$student AND copy=$copy',
                      {
                        $student: req.body.student,
                        $copy: req.body.copy,
                      },
                      () => {
                        db(
                          'run',
                          'DELETE FROM scoring_mark WHERE student=$student AND copy=$copy',
                          {
                            $student: req.body.student,
                            $copy: req.body.copy,
                          },
                          () => {
                            db(
                              'run',
                              'DELETE FROM scoring_code WHERE student=$student AND copy=$copy',
                              {
                                $student: req.body.student,
                                $copy: req.body.copy,
                              },
                              () => {
                                db(
                                  'run',
                                  'DELETE FROM association_association WHERE student=$student AND copy=$copy',
                                  {
                                    $student: req.body.student,
                                    $copy: req.body.copy,
                                  },
                                  async () => {
                                    await redisClient.HSET(
                                      'project:' +
                                        req.params.project +
                                        ':status',
                                      'scanned',
                                      new Date().getTime().toString()
                                    );
                                    res.sendStatus(200);
                                  }
                                );
                              }
                            );
                          }
                        );
                      }
                    );
                  }
                );
              }
            );
          }
        );
      }
    );
  });
});

/* ZONES */

app.get(
  '/project/:project/zones/:student/:page::copy',
  aclProject,
  (req, res) => {
    database(req, res, (db) => {
      const query =
        'SELECT z.id_a AS question, z.id_b AS answer, z.total, z.black, ' +
        'z.manual, max(CASE WHEN p.corner = 1 THEN p.x END) as x0, ' +
        'max(CASE WHEN p.corner = 1 THEN p.y END) as y0, ' +
        'max(CASE WHEN p.corner = 2 THEN p.x END) as x1, ' +
        'max(CASE WHEN p.corner = 2 THEN p.y END) as y1, ' +
        'max(CASE WHEN p.corner = 3 THEN p.x END) as x2, ' +
        'max(CASE WHEN p.corner = 3 THEN p.y END) as y2, ' +
        'max(CASE WHEN p.corner = 4 THEN p.x END) as x3, ' +
        'max(CASE WHEN p.corner = 4 THEN p.y END) as y3 ' +
        'FROM capture_zone AS z ' +
        'JOIN capture_position as p ON z.zoneid=p.zoneid ' +
        'WHERE z.student=$student AND z.page=$page AND z.copy=$copy AND z.type=4 AND p.type=1 ' +
        'GROUP BY z.zoneid, z.id_a, z.id_b, z.total, z.black, z.manual ' +
        'ORDER BY min(p.y), min(p.y)';
      db(
        'all',
        query,
        {
          $student: req.params.student,
          $page: req.params.page,
          $copy: req.params.copy,
        },
        (rows) => {
          res.json(rows);
        }
      );
    });
  }
);

/* GRADES */

app.get('/project/:project/scoring', aclProject, (req, res) => {
  const PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
  const project = req.params.project;

  projectOptions(req.params.project, (_err, result) => {
    amcCommande(
      null,
      PROJECT_FOLDER,
      project,
      'computing scoring data',
      [
        'prepare',
        '--mode',
        'b',
        '--n-copies',
        result.project.nombre_copies,
        'source.tex',
        '--prefix',
        PROJECT_FOLDER,
        '--data',
        PROJECT_FOLDER + 'data',
        '--latex-stdout',
      ],
      (logScoring) => {
        res.json(logScoring);
      }
    );
  });
});

app.post('/project/:project/csv', aclProject, (req, res) => {
  const filename = path.resolve(
    PROJECTS_FOLDER,
    req.params.project + '/students.csv'
  );
  fs.writeFile(filename, req.body, function (err: any) {
    if (err) {
      res.sendStatus(500).end();
      return;
    } else {
      //try auto-match
      //TODO get 'etu' from scoring_code?
      amcCommande(
        res,
        PROJECTS_FOLDER + '/' + req.params.project,
        req.params.project,
        'matching students',
        [
          'association-auto',
          '--data',
          PROJECTS_FOLDER + '/' + req.params.project + '/data',
          '--notes-id',
          'etu',
          '--liste',
          filename,
          '--liste-key',
          'id',
        ],
        (log) => {
          res.json({log: log});
        }
      );
    }
  });
});

app.get('/project/:project/csv', aclProject, (req, res) => {
  if (!req.user) return res.sendStatus(403);
  userSaveVisit(req.user.username, req.params.project);
  res.sendFile(
    path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv')
  );
});

app.get('/project/:project/gradefiles', aclProject, async (req, res) => {
  try {
    const data = await redisClient.GET(
      'project:' + req.params.project + ':gradefiles'
    );
    res.send(data);
  } catch (e) {
    res.send([]);
  }
});

app.post('/project/:project/gradefiles', aclProject, async (req, res) => {
  await redisClient.SET(
    'project:' + req.params.project + ':gradefiles',
    JSON.stringify(req.body)
  );
  res.sendStatus(200);
});

//could do in db directly?
app.post('/project/:project/association/manual', aclProject, (req, res) => {
  amcCommande(
    res,
    PROJECTS_FOLDER + '/' + req.params.project,
    req.params.project,
    'matching students',
    [
      'association',
      '--data',
      PROJECTS_FOLDER + '/' + req.params.project + '/data',
      '--set',
      '--student',
      req.body.student,
      '--copy',
      req.body.copy,
      '--id',
      req.body.id,
    ],
    (log) => {
      res.json({log: log});
    }
  );
});

app.get('/project/:project/names', aclProject, (req, res) => {
  // LIST OF STUDENTS with their name field and if matched
  database(req, res, (db) => {
    const query =
      'SELECT p.student, p.page, p.copy, z.image, a.manual, a.auto ' +
      'FROM capture_page p JOIN layout.layout_zone l ON p.student=l.student AND p.page = l.page AND l.zone="__n"' +
      'LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy ' +
      'LEFT JOIN assoc.association_association a ON a.student = p.student AND a.copy = p.copy';

    db('all', query, (rows) => {
      res.json(rows);
    });
  });
});

function calculateMarks(
  project: string,
  callback?: (log: string) => void
): void {
  const PROJECT_FOLDER = PROJECTS_FOLDER + '/' + project + '/';
  projectOptions(project, (_err, result) => {
    projectThreshold(project, (_err2, threshold) => {
      amcCommande(
        null,
        PROJECT_FOLDER,
        project,
        'calculating marks',
        [
          'note',
          '--data',
          PROJECT_FOLDER + 'data',
          '--seuil',
          threshold,
          '--grain',
          result.project.note_grain,
          '--arrondi',
          result.project.note_arrondi,
          '--notemin',
          result.project.note_min,
          '--notenull',
          result.project.note_null,
          '--notemax',
          result.project.note_max,
          '--plafond',
          '--progression-id',
          'notation',
          '--progression',
          '1',
        ],
        async (log) => {
          await redisClient.HSET(
            'project:' + project + ':status',
            'marked',
            new Date().getTime().toString()
          );
          if (callback) {
            callback(log);
          }
        }
      );
    });
  });
}

app.get('/project/:project/mark', aclProject, (req, res) => {
  calculateMarks(req.params.project, (log) => {
    res.json(log);
  });
});

app.get('/project/:project/scores', aclProject, async (req, res) => {
  function getScores(): void {
    database(req, res, (db) => {
      const query =
        'SELECT COALESCE(aa.manual, aa.auto) AS id, ss.*, st.title, lb.page ' +
        'FROM scoring_score ss ' +
        'JOIN scoring_title st ON ss.question = st.question ' +
        'JOIN scoring_question sq ON ss.question = sq.question AND ' +
        'ss.student = sq.student AND sq.indicative = 0 ' +
        'LEFT JOIN association_association aa ON aa.student = ss.student AND aa.copy = ss.copy ' +
        'LEFT JOIN (SELECT student, page, question FROM layout_box GROUP BY student, page, question) lb ON lb.student = ss.student AND lb.question = ss.question ' +
        'ORDER BY id, student, copy, title';

      db('all', query, (rows) => {
        res.json(rows);
      });
    });
  }

  //check if we need to update markings
  const results = await redisClient.HMGET(
    'project:' + req.params.project + ':status',
    ['scanned', 'marked']
  );
  if (results[0] > results[1]) {
    calculateMarks(req.params.project, getScores);
  } else {
    getScores();
  }
});

/* REPORT */

app.get('/project/:project/ods', aclProject, (req, res) => {
  const filename = path.resolve(
    PROJECTS_FOLDER,
    req.params.project + '/students.csv'
  );
  const exportFile = path.resolve(
    PROJECTS_FOLDER,
    req.params.project + '/exports/export.ods'
  );
  amcCommande(
    res,
    PROJECTS_FOLDER + '/' + req.params.project,
    req.params.project,
    'generating ods',
    [
      'export',
      '--module',
      'ods',
      '--data',
      PROJECTS_FOLDER + '/' + req.params.project + '/data',
      '--useall',
      '1',
      '--sort',
      'l',
      '--fich-noms',
      filename,
      '--output',
      exportFile,
      '--option-out',
      'nom=' + req.params.project,
      '--option-out',
      'groupsums=1',
      '--option-out',
      'stats=1',
      '--option-out',
      'columns=student.copy,student.key,student.name',
      '--option-out',
      'statsindic=1',
    ],
    () => {
      res.attachment('export.ods');
      res.sendFile(exportFile);
    }
  );
});

/*
ANNOTATE

*/

app.post('/project/:project/annotate', aclProject, async (req, res) => {
  if (!req.user) return res.sendStatus(403);
  const locked = await redisClient.HGET(
    'project:' + req.params.project + ':status',
    'locked'
  );
  if (locked === '1') {
    return res.status(409).end('ALREADY WORKING!');
  }
  res.sendStatus(200);
  ws.to(req.params.project + '-notifications').emit('annotate', {
    action: 'start',
  });
  await redisClient.HSET('project:' + req.params.project + ':status', {
    locked: 1,
    annotated: '',
  });
  projectOptions(req.params.project, (_err, result) => {
    tmp.file((_err, tmpFile, _fd, cleanup) => {
      const filename = path.resolve(
        PROJECTS_FOLDER,
        req.params.project + '/students.csv'
      );

      const symbols =
        '0-0:' +
        result.project.symbole_0_0_type +
        '/' +
        result.project.symbole_0_0_color +
        ',0-1:' +
        result.project.symbole_0_1_type +
        '/' +
        result.project.symbole_0_1_color +
        ',1-0:' +
        result.project.symbole_1_0_type +
        '/' +
        result.project.symbole_1_0_color +
        ',1-1:' +
        result.project.symbole_1_1_type +
        '/' +
        result.project.symbole_1_1_color;
      // https://gitlab.com/jojo_boulix/auto-multiple-choice/-/blob/master/AMC-gui.pl.in
      const params = [
        'annotate',
        '--progression-id',
        'annotate',
        '--progression',
        '1',
        '--cr',
        PROJECTS_FOLDER + '/' + req.params.project + '/cr',
        '--project',
        PROJECTS_FOLDER + '/' + req.params.project,
        '--projects',
        PROJECTS_FOLDER,
        '--data',
        PROJECTS_FOLDER + '/' + req.params.project + '/data/',
        '--subject',
        PROJECTS_FOLDER + '/' + req.params.project + '/sujet.pdf',
        '--filename-model',
        result.project.modele_regroupement || '(ID)',
        '--force-ascii', //TODO  try without but fix url
        '--sort',
        result.project.export_sort || 'l',
        '--line-width',
        '2',
        '--font-name',
        'Lato Regular 12',
        '--symbols',
        symbols,
        '--no-indicatives', // symboles_indicatives
        '--position',
        result.project.annote_position,
        '--dist-to-box', // used for position = case
        '1cm', // TODO maybe as option
        '--dist-margin',
        '1cm',
        '--dist-margin-global',
        '1cm',
        '--n-digits',
        '2',
        '--verdict',
        result.project.verdict,
        '--verdict-question',
        result.project.verdict_q,
        'verdict-question-cancelled',
        result.project.verdict_qc,
        '--names-file',
        filename,
        '--csv-build-name',
        '(nom|surname) (prenom|name)',
        '--no-rtl',
        '--changes-only', // test if it works or generates problems
        '0',
        '--embedded-max-size',
        '1000x1500',
        'embedded-jpeg-quality',
        '90',
        '--embedded-format',
        'jpeg',
        '--with',
        'pdflatex',
        '--filter',
        'latex',
      ];
      if (req.body.ids) {
        req.body.ids.forEach((id: number) => {
          fs.writeFileSync(tmpFile, String(id));
        });
        params.push('--id-file');
        params.push(tmpFile);
      } else {
        // annotate all but clear folder first
        fs.emptyDirSync(
          PROJECTS_FOLDER + '/' + req.params.project + '/cr/corrections/pdf'
        );
      }
      amcCommande(
        null,
        PROJECTS_FOLDER + '/' + req.params.project,
        req.params.project,
        'annotating pages',
        params,
        async () => {
          cleanup();
          commitGit(req.params.project, req.user?.username || '', 'annotate');
          await redisClient.HSET('project:' + req.params.project + ':status', {
            locked: 0,
            annotated: new Date().getTime(),
          });

          function respond(filename?: string): void {
            ws.to(req.params.project + '-notifications').emit('annotate', {
              action: 'end',
              type: req.body.ids ? 'single' : 'all',
              file: filename,
            });
          }

          function databaseReport(
            project: string,
            student: number,
            copy: number,
            callback: (filename?: string) => void
          ): void {
            const db = new sqlite3.Database(
              PROJECTS_FOLDER + '/' + project + '/data/report.sqlite',
              (err) => {
                if (err) {
                  callback(undefined);
                }
                /*
                    type:
REPORT_ANNOTATED_PDF        => 1,
REPORT_SINGLE_ANNOTATED_PDF => 2,
REPORT_PRINTED_COPY         => 3,
REPORT_ANONYMIZED_PDF       => 4,
                    */
                db.all(
                  'SELECT file FROM report_student WHERE student=$student AND copy=$copy AND type=1',
                  {$student: student, $copy: copy},
                  (_err, rows: any[]) => {
                    let filename = undefined;
                    if (rows && rows.length > 0) {
                      filename = 'cr/corrections/pdf/' + rows[0].file;
                    }
                    callback(filename);
                  }
                );
              }
            );
          }

          if (req.body.ids) {
            req.body.ids.forEach((id: any) => {
              let student = id;
              let copy = 0;
              if (isNaN(id)) {
                [student, copy] = id.split(':');
              }
              databaseReport(
                req.params.project,
                Number(student),
                Number(copy),
                respond
              );
            });
          } else {
            respond(undefined);
          }
        }
      );
    });
  });
});

app.get('/project/:project/zip/annotate', aclProject, (req, res) => {
  const zip = archiver('zip');
  res.on('close', function () {
    return res.end();
  });
  res.attachment(req.params.project + '_annotate.zip');
  zip.pipe(res);
  zip.directory(
    PROJECTS_FOLDER + '/' + req.params.project + '/cr/corrections/pdf',
    'annotate'
  );
  zip.file(APP_FOLDER + '/assets/extractFirstPage.bat', {
    name: 'extractFirstPage.bat.txt',
  });
  zip.file(APP_FOLDER + '/assets/print.bat', {name: 'print.bat.txt'});
  zip.finalize();
});

function mergePdfs(
  project: string,
  correctionsFolder: string,
  destinationFile: string
) {
  const params = [
    '-c',
    `find ${correctionsFolder} -type f -name '*.pdf' -print0 | sort -z | xargs -0 gs -q -dBATCH -dNOPAUSE -dSAFER -sDEVICE=pdfwrite -sOUTPUTFILE=${destinationFile}`,
  ];
  const cwd = `${PROJECTS_FOLDER}/${project}/cr/corrections`;
  return new Promise((resolve, reject) => {
    const ps = childProcess.spawn('sh', params, {cwd});

    ps.on('close', (code: number) => {
      if (code !== 0) {
        reject(`mergepdf process exited with code ${code}`);
      } else {
        resolve(destinationFile);
      }
    });
  });
}

app.get(
  '/project/:project/merged/all',
  aclProject,
  async (req: express.Request, res: express.Response) => {
    try {
      await mergePdfs(req.params.project, 'pdf', 'combined_all.pdf');
      res.sendFile(
        `${PROJECTS_FOLDER}/${req.params.project}/cr/corrections/combined_all.pdf`
      );
    } catch (err) {
      console.log(err);
      res.sendStatus(500);
    }
  }
);

function extractFirstPage(project: string) {
  const params = [
    '-c',
    `for file in *.pdf; do gs -dBATCH -dNOPAUSE -dSAFER -sDEVICE=pdfwrite -dFirstPage=1 -dLastPage=1 -sOutputFile="../pdf_firstpage/$file" "$file"; done`,
  ];
  const cwd = `${PROJECTS_FOLDER}/${project}/cr/corrections/pdf`;
  return new Promise((resolve, reject) => {
    const ps = childProcess.spawn('sh', params, {cwd});

    ps.on('close', (code: number) => {
      if (code !== 0) {
        reject(`extractpdf process exited with code ${code}`);
      } else {
        resolve('done');
      }
    });
  });
}

app.get(
  '/project/:project/merged/firstpage',
  aclProject,
  async (req: express.Request, res: express.Response) => {
    try {
      fs.rmSync(
        `${PROJECTS_FOLDER}/${req.params.project}/cr/corrections/pdf_firstpage`,
        {recursive: true, force: true}
      );
      fs.mkdirSync(
        `${PROJECTS_FOLDER}/${req.params.project}/cr/corrections/pdf_firstpage`
      );
      await extractFirstPage(req.params.project);
      await mergePdfs(
        req.params.project,
        'pdf_firstpage',
        'combined_firstpage.pdf'
      );
      res.sendFile(
        `${PROJECTS_FOLDER}/${req.params.project}/cr/corrections/combined_firstpage.pdf`
      );
    } catch (err) {
      console.log(err);
      res.sendStatus(500);
    }
  }
);

/*

scoring_score
# * why is a small string that is used to know when special cases has
#   been encountered:
#
#     E means syntax error (several boxes ticked for a simple
#     question, or " none of the above" AND another box ticked for a
#     multiple question).
#
#     V means that no box are ticked.
#
#     P means that a floor has been applied.


*/

app.get('/project/:project/stats', aclProject, (req, res) => {
  //TODO check when updated in db vs options file?
  database(req, res, (db) => {
    let query =
      "SELECT value FROM scoring.scoring_variables WHERE name='darkness_threshold'";
    db('get', query, (setting: any) => {
      let threshold = 0.5; //TODO change?
      if (setting && setting.value) {
        threshold = setting.value;
      }
      database(req, res, (db) => {
        query =
          'SELECT t.question, t.title, q.indicative, q.type, s.max, AVG(s.score) / s.max AS avg ' +
          'FROM scoring.scoring_title t JOIN scoring.scoring_question q ON  t.question = q.question ' +
          'LEFT JOIN scoring.scoring_score s ON s.question = t.question ' +
          "WHERE q.strategy <> 'auto=0' " +
          'GROUP BY t.question, t.title, q.indicative, q.type, s.max ' +
          'ORDER BY t.question';

        db('all', query, (questionsList) => {
          const questions: any = {};
          questionsList.forEach((question: any) => {
            question.answers = [];
            questions[question.question] = question;
          });
          database(req, res, (db) => {
            query =
              "SELECT question, 'all' AS answer, COUNT(*) AS nb, " +
              '0 as correct ' +
              'FROM scoring.scoring_score ' +
              'GROUP BY question ' +
              'UNION ' +
              "SELECT question, 'invalid' AS answer, COUNT(*)-COUNT(NULLIF(why,'E')) AS nb, " +
              '3 as correct ' +
              'FROM scoring.scoring_score ' +
              'GROUP BY question ' +
              'UNION ' +
              "SELECT question, 'empty' AS answer, COUNT(*)-COUNT(NULLIF(why,'V')) AS nb, " +
              '2 as correct ' +
              'FROM scoring.scoring_score ' +
              'GROUP BY question ' +
              'UNION ' +
              'SELECT s.question AS question, z.id_b AS answer, ' +
              'SUM(CASE ' +
              "WHEN s.why='V' THEN 0 " +
              "WHEN s.why='E' THEN 0 " +
              'WHEN z.manual >= 0 THEN z.manual ' +
              'WHEN z.total<=0 THEN 0 ' +
              'WHEN z.black >= $threshold * z.total THEN 1 ' +
              'ELSE 0 ' +
              'END) AS nb, a.correct AS correct ' +
              'FROM capture_zone z JOIN scoring.scoring_score s ' +
              'ON z.student = s.student AND ' +
              'z.copy = s.copy AND ' +
              's.question = z.id_a ' +
              'AND z.type = 4 ' +
              'JOIN scoring.scoring_answer a ON a.student = s.student ' +
              'AND a.question = s.question ' +
              'AND z.id_b = a.answer ' +
              'GROUP BY z.id_a, z.id_b, a.correct';

            db('all', query, {$threshold: threshold}, (rows) => {
              rows.forEach((row: any) => {
                if (questions[row.question]) {
                  if (row.answer === 'all') {
                    questions[row.question].total = row.nb;
                  } else {
                    questions[row.question].answers.push(row);
                  }
                }
              });
              res.json(
                questionsList.map((q) => {
                  return questions[q.question];
                })
              );
            });
          });
        });
      });
    });
  });
});

//for acl middlware we have to handle its custom httperror
app.use(
  (
    err: any,
    _req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    // Move on if everything is alright
    if (!err) {
      return next();
    }
    // Something is wrong, inform user
    if (err.errorCode && err.message) {
      res.status(err.errorCode).json(err.message);
    } else if (err.status && err.name) {
      res.status(err.status).json(err.name);
    } else {
      console.log('custom_error_handler_skip:', err);
      console.log(Object.keys(err));
      next(err);
    }
  }
);

if (env === 'development') {
  app.use(errorHandler({log: true}));
  // for coverage report
  app.get('/debug-exit', () => {
    process.exit();
  });
}

httpServer.listen(process.env.SERVER_PORT);
httpServer.on('listening', function () {
  const address = httpServer.address();
  console.log(
    'server listening on port %d in %s mode',
    typeof address === 'string' ? address : address?.port,
    app.settings.env
  );
});

export const App = app;
