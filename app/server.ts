///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
import raven = require('raven');
import fs = require('fs-extra');
import StreamSplitter = require("stream-splitter");
import cors = require('cors');
import express = require('express');
import io = require('socket.io');
import bodyParser = require('body-parser');
import errorHandler = require('errorhandler');
import sqlite3 = require('sqlite3');
import path = require('path');
import jwt = require('jsonwebtoken');
import socketioJwt = require('socketio-jwt');
import expressJwt = require('express-jwt');
import bcrypt = require('bcrypt');
import redis = require('redis');
import xml2js = require('xml2js');
import mkdirp = require('mkdirp');
import Acl = require('acl');
import multiparty = require('connect-multiparty');
import tmp = require('tmp');
import childProcess = require('child_process');
import git = require('simple-git');
import u2f = require('u2f');
//import AdmZip = require('adm-zip');
import archiver = require('archiver');
import slug = require('slug');
slug.defaults.mode = 'rfc3986';

import sizeOf = require('image-size');
import diffSync= require('diffsync');
import redisDataAdapter = require('./diffsyncredis');

var ravenClient = new raven.Client( process.env.SENTRY_DSN || '');
ravenClient.patchGlobal(function(sent, err) {
  console.log('patchGlobal', err.stack);
  process.exit(1);
});

var multipartMiddleware = multiparty();

var APP_FOLDER = path.resolve(__dirname, '../app/');
var PROJECTS_FOLDER = path.resolve(__dirname, '../projects/');

var redisClient = redis.createClient(process.env.REDIS_PORT_6379_TCP_PORT, process.env.REDIS_PORT_6379_TCP_ADDR, {});
redisClient.on('error', function (err) {
    console.log('Redis error ' + err);
    ravenClient.captureException(err);
});
var acl = new Acl(new Acl.redisBackend(redisClient, 'acl')
/*
    , {debug: (txt) => {
    console.log(JSON.stringify(txt));
}}
*/);

var app = express();
app.use(raven.middleware.express.requestHandler(process.env.SENTRY_DSN));
var server = require('http').Server(app);
var ws = io(server);


ws.use(socketioJwt.authorize({
    secret: process.env.JWT_SECRET,
    timeout: 15000, // 15 seconds to send the authentication message
    handshake: true
}));

//in memory rooms users list
var rooms = {};

function userSaveVisit(username, projectName) {
    redisClient.zadd('user:' + username + ':recent', new Date().getTime(), projectName);
    redisClient.zremrangebyrank('user:' + username + ':recent', 0, -11);
}

ws.on('connection', (socket) => {
    //this socket is authenticated, we are good to handle more events from it.
    var username = (<any>socket).decoded_token.username;
    socket.on('listen', (project) => {
        acl.hasRole(username, project, (err, hasRole) => {
            if (!hasRole) {
                socket.disconnect(true);
            } else {
                userSaveVisit(username, project);
                socket.join(project + '-notifications');
                socket.on('disconnect', function() {
                    delete rooms[project][socket.id];
                    ws.to(project + '-notifications').emit('user:disconnected', {id: socket.id, username: username});
                });

                if (!rooms.hasOwnProperty(project)){
                    rooms[project] = {};
                }
                socket.emit('user:online', rooms[project]);
                rooms[project][socket.id] = {id: socket.id, username: username};
                ws.to(project + '-notifications').emit('user:connected', {id: socket.id, username: username});
            }
        });
    });

    socket.on('diffsync-join', (data) => {
        acl.hasRole(username, data, (err, hasRole) => {
            if (!hasRole) {
                socket.disconnect(true);
            }
        });
    });

    socket.on('diffsync-send-edit', (data) => {
        var room = data;
        if (data.hasOwnProperty('room')){
            room = data.room;
        }
        acl.hasRole(username, room, (err, hasRole) => {
            if (!hasRole) {
                socket.disconnect(true);
            }
        });
    });
});

var dataAdapter = new redisDataAdapter(redisClient, 'exam');
var diffSyncServer = new diffSync.Server(dataAdapter, ws);
console.log('diffSyncServer started', diffSyncServer.adapter.namespace); //ts lint

var env = process.env.NODE_ENV || 'development';
if (env === 'development') {
    sqlite3.verbose();
}
else if (env === 'production') {
    app.use(express.static(__dirname + '/public'));
}

app.use(cors({
    origin: true,
    credentials: true,
    exposedHeaders: ['Accept-Ranges', 'Content-Encoding', 'Content-Length', 'Content-Range']
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit: '50mb'}));
app.use(function(req, res, next){
  if (req.is('text/*')) {
    req.body = '';
    req.setEncoding('utf8');
    req.on('data', function(chunk){
        req.body += chunk;
    });
    req.on('end', next);
  } else {
    next();
  }
});

var secure = expressJwt({
    secret: process.env.JWT_SECRET,
    getToken: function fromHeaderOrQuerystring (req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
            return req.query.token;
        }
        return null;
    }
});
//secure /project with auth api
app.use('/project', secure);
app.use('/admin', secure);
app.use('/profile', secure);


let aclProject: express.RequestHandler = <express.RequestHandler>acl.middleware(2, (req: express.Request, res) => {
        return req.user.username;
    }, 'admin');

let aclAdmin: express.RequestHandler = <express.RequestHandler>acl.middleware(1, (req: express.Request, res) => {
        return req.user.username;
    }, 'admin');



function database(req, res, callback){
    var project = req.params.project;
    var db = new sqlite3.Database(PROJECTS_FOLDER + '/' + project + '/data/capture.sqlite', (err) => {
        if (err){
            res.status(500).end(JSON.stringify(err));
            return;
        }
        db.exec("ATTACH DATABASE '" + PROJECTS_FOLDER + '/' + project + "/data/layout.sqlite' AS layout", () => {
            db.exec("ATTACH DATABASE '" + PROJECTS_FOLDER + '/' + project + "/data/association.sqlite' AS assoc", () => {
                db.exec("ATTACH DATABASE '" + PROJECTS_FOLDER + '/' + project + "/data/scoring.sqlite' AS scoring", () => {
                    var dbHandled = (method, query, params, success) => {
                        var internalCallback = (err, rows) => {
                            if (err){
                                res.status(500).end(JSON.stringify(err));
                                return;
                            }
                            if (success){
                                success(rows);
                            } else {
                                params(rows);
                            }
                        };

                        if (success){
                            db[method](query, params, internalCallback);
                        } else {
                            db[method](query, internalCallback);
                        }
                    };
                    callback(dbHandled);
                });
            });
        });
    });
}

function projectOptions(project: string, callback: (err, res) => void) {
    var filename = path.resolve(PROJECTS_FOLDER, project + '/options.xml');
    fs.readFile(filename, 'utf-8', function(err, data) {
        if (err){
            callback(err, null);
        } else {
            xml2js.parseString(data, {explicitArray: false}, callback);
        }
    });
}

function projectThreshold(project: string, callback: (err, res) => void) {
    projectOptions(project, (err, result) => {
        var threshold = 0.5;
        if (result.projetAMC.seuil && !isNaN(result.projetAMC.seuil)){
            threshold = parseFloat(result.projetAMC.seuil);
        }
        callback(null, threshold);
    });
}

function amcCommande(res, cwd, project: string, msg: string, params: string[], callback, error?){
    ws.to(project + '-notifications').emit('log', {command: params[0], msg: msg, action: 'start', params: params});
    var amc = childProcess.spawn('auto-multiple-choice', params, {
        cwd: cwd
    });

    var log = '';
    var errorlog = '';

    //send complete lines
    var splitter = amc.stdout.pipe(StreamSplitter('\n'));
    splitter.encoding = 'utf8';
    splitter.on('token', function(token) {
       log += token + '\n';
       ws.to(project + '-notifications').emit('log', {command: params[0], msg: msg, action: 'log', data: token});
    });

    amc.stderr.on('data', (data) => {
        errorlog += data;
        ws.to(project + '-notifications').emit('log', {command: params[0], msg: msg,  action: 'err', data: data.toString()});
    });
    amc.on('close', (code) => {
        ws.to(project + '-notifications').emit('log', {command: params[0], msg: msg,  action: 'end', code: code});
        if (code === 0){
            if (callback){
                callback(log);
            }
        } else {
            redisClient.hset('project:' + project + ':status', 'locked', 0);
            if (error) {
                error();
            }
            if (res) {
                res.json({
                    log: log,
                    command: params,
                    errorlog: errorlog,
                    error: code});
            }
        }
    });
}

app.get('/', (req, res) => {
    res.send('AMCUI API SERVER');
});

app.get('/testerror', (req, res) => {
    throw 'Error Test';
});

app.get('/testraven', (req, res) => {
    try {
        throw 'Error Test Raven';
    } catch (e) {
        ravenClient.captureException(e);
        res.send('error catched and sent');
    }
});

acl.allow('admin', '/admin', 'admin');
acl.addUserRoles('boris', 'admin');

app.get('/admin/stats', aclAdmin, (req, res) => {
    var stats = {users: {}, projects: {}};
    redisClient.smembers('acl_meta@roles', (err, roles) => {
        redisClient.smembers('acl_meta@users', (err, users) => {
            var i = 0;
            users.forEach((user) => {
                stats.users[user] = [];
                acl.userRoles(user, (err, uroles) => {
                    stats.users[user] = uroles;
                    i++;
                    if (i === users.length){
                        let s = 0;
                        let g = 0;
                        roles.forEach((project) => {
                            let p = {
                                students: undefined,
                                commits: undefined,
                            };
                            stats.projects[project] = p;
                            countStudentsCSV(project, (r) => {
                                p.students = r;
                                s++;
                                if (s === roles.length && g === roles.length) {
                                    res.json(stats);
                                }
                            });
                            countGitCommits(project, (r) => {
                                p.commits = r;
                                g++;
                                if (s === roles.length && g === roles.length) {
                                    res.json(stats);
                                }
                            });
                        });
                    }
                });
            });
        });
    });
});

function countStudentsCSV(project, callback) {
    let filename = path.resolve(PROJECTS_FOLDER, project + '/students.csv');
    fs.readFile(filename, (err, data) => {
        if (err) {
            callback(-1);
        } else {
            callback(data.toString('utf8').split('\n').length - 1);
        }
    });
}

function countGitCommits(project, callback){
    var g = git(PROJECTS_FOLDER + '/' + project);
    g._run(['rev-list', '--count', 'master'], (err, data) => {
        if (err) {
            callback(-1);
        } else {
            callback(Number(data.trim()));
        }
    });
}

app.get('/admin/du', aclAdmin, (req, res) => {
        let size = childProcess.spawn('du', ['-k', '-d 2'], {cwd: PROJECTS_FOLDER});
        size.stdout.setEncoding('utf8');
        let projects = {};
        let re = /(\d+)[\t ]+\.\/([^\/]*)\/?(.*)/;
        let splitter = size.stdout.pipe(StreamSplitter('\n'));
        splitter.encoding = 'utf8';
        splitter.on('token', function(data) {
            let entry = re.exec(data.trim());
            if (entry === null) {
                return;
            }
            if (!projects.hasOwnProperty(entry[2])) {
                projects[entry[2]] = {total: 0, folders: []};
            }
            if (entry[3] === '') {
                projects[entry[2]].total = Number(entry[1]);
            } else {
                let folder = {};
                folder[entry[3]] = Number(entry[1]);
                projects[entry[2]].folders.push(folder);
            }
        });

        size.on('exit', function (code) {
            Object.keys(projects).forEach((k) => {
                let p = projects[k];
                let sum = p.folders.reduce((total, f) => {
                    return total + f[Object.keys(f)[0]];
                }, 0);
                p.folders.push({'.': p.total - sum});
            });
            res.json(projects);
        });
});

app.post('/admin/import', aclAdmin, (req, res) => {
    // Warning, does not check if project folder is valid
    addProjectAcl(req.body.project, req.user.username);
    res.sendStatus(200);
});

app.post('/admin/addtoproject', aclAdmin, (req, res) => {
    acl.addUserRoles(req.user.username, req.body.project);
    let msg = `ADMIN: ${req.user.username} added himself to ${req.body.project}`;
    console.log(msg);
    ravenClient.captureMessage(msg);
    res.sendStatus(200);
});

app.post('/admin/removefromproject', aclAdmin, (req, res) => {
    acl.removeUserRoles(req.user.username, req.body.project);
    let msg = `ADMIN: ${req.user.username} removed himself from ${req.body.project}`;
    console.log(msg);
    ravenClient.captureMessage(msg);
    res.sendStatus(200);
});

/*
TODO

Change options of a project
	-> some trigger other functions? (marks, annotations)

Upload a project?

Edit Latex
	-> recompute markings?

Print
   ->before check layout (user interaction?)

save formulas
save custom csv data


REFACTOR
all file/folder names

*/
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
app.post('/login', (req, res, next) => {
    if (req.body.username) {
        var username = req.body.username.toLowerCase();
        var sendToken = (user) => {
            try {
                delete user.password;
                delete user.keyHandle;
                delete user.publicKey;
                delete user.u2fRequest;
                var token = jwt.sign(user, process.env.JWT_SECRET, {expiresIn: '6h'});
                res.json({token: token});
            } catch (e) {
                console.log('login', e, user);
                res.status(500).send(e);
            }
        };
        redisClient.get('user:' + username, function(err, reply) {
            var u2fAnswer;

            if (reply) {
                var user = JSON.parse(reply);

                if (req.body.u2f){
                    if (user.u2f){
                        u2fAnswer = u2f.checkSignature(user.u2fRequest, req.body.u2f, user.publicKey);
                        if (u2fAnswer.successful) {
                            sendToken(user);
                        } else {
                            res.sendStatus(500);
                        }
                    } else {
                        u2fAnswer = u2f.checkRegistration(user.u2fRequest, req.body.u2f);
                        if (u2fAnswer.successful) {
                            user.u2f = true;
                            user.keyHandle = u2fAnswer.keyHandle;
                            user.publicKey = u2fAnswer.publicKey;
                            redisClient.set('user:' + user.username, JSON.stringify(user), (err) => {
                                if (err) {
                                    res.sendStatus(500);
                                } else {
                                    sendToken(user);
                                }
                            });
                        } else {
                            res.sendStatus(500);
                        }
                    }

                } else if (bcrypt.compareSync(req.body.password, user.password)) {
                    if (!user.u2f && req.body.u2fRegistration) {
                        //handle u2f key registration
                        user.u2fRequest = u2f.request(process.env.SITE_URL);
                        //store u2fRequest in user
                        redisClient.set('user:' + user.username, JSON.stringify(user), (err) => {
                            if (err) {
                                res.sendStatus(500);
                            } else {
                                res.json({
                                    u2f: user.u2fRequest
                                });
                            }
                        });
                    } else if (user.u2f) {
                        //handle u2f key validation
                        user.u2fRequest = u2f.request(process.env.SITE_URL, user.keyHandle);
                        //store u2fRequest in user
                        redisClient.set('user:' + user.username, JSON.stringify(user), (err) => {
                            if (err) {
                                res.sendStatus(500);
                            } else {
                                res.json({
                                    u2f: user.u2fRequest
                                });
                            }
                        });

                    } else{
                        sendToken(user);
                    }
                } else {
                    res.status(401).send('Wrong user or password');
                }
            } else {
                //create Account
                var password = bcrypt.hashSync(req.body.password, 10);
                var newUser = {username: username, password: password};
                redisClient.set('user:' + newUser.username, JSON.stringify(newUser), (err) => {
                    if (err) {
                        res.sendStatus(500);
                    } else {
                        sendToken(newUser);
                    }
                });
            }
        });
    } else {
        res.sendStatus(400);
    }
});

app.post('/profile/removeU2f', (req, res, next) => {
    redisClient.get('user:' + req.user.username, function(err, reply) {
        if (reply) {
            var user = JSON.parse(reply);
            delete user.keyHandle;
            delete user.publicKey;
            delete user.u2fRequest;
            delete user.u2f;
            redisClient.set('user:' + user.username, JSON.stringify(user), (err) => {
                if (err) {
                    res.sendStatus(500);
                } else {
                    res.sendStatus(200);
                }
            });
        } else {
            res.sendStatus(401);
        }
    });
});

app.post('/changePassword', (req, res, next) => {
    if (req.body.password && req.body.username && req.body.newPassword) {
        var username = req.body.username.toLowerCase();
        redisClient.get('user:' + username, function(err, reply) {
            if (reply) {
                var user = JSON.parse(reply);
                if (bcrypt.compareSync(req.body.password, user.password)) {
                    user.password = bcrypt.hashSync(req.body.newPassword, 10);
                    redisClient.set('user:' + user.username, JSON.stringify(user), (err) => {
                        if (err) {
                            res.sendStatus(500);
                        } else {
                            res.sendStatus(200);
                        }
                    });
                } else {
                    res.status(404).send('Wrong user or password');
                }
            } else {
                res.status(404).send('Wrong user or password');
            }
        });
    } else {
        res.status(404).send('Wrong user or password');
    }
});

app.get('/project/list', (req, res) => {
    acl.userRoles(req.user.username, (err, roles) => {
        var projects = [];
        roles.forEach((role, idx) => {
            redisClient.hgetall('project:' + role + ':status', (err2, status) => {
                acl.roleUsers(role, (err, users) => {
                    projects.push({project: role, status: status, users: users});
                    if (projects.length === roles.length){
                        res.json(projects);
                    }
                });
            });
        });
    });
});

app.get('/project/recent', (req, res) => {
    redisClient.zrevrange('user:' + req.user.username + ':recent', 0, -1, (err, list) => {
        if (err) {
            res.json([]);
        } else {
            res.json(list);
        }
    });
});


function addProjectAcl(project, username) {
    //role, resource, permission
    acl.allow(project, '/project/' + project, 'admin');
    //user, role
    acl.addUserRoles(username, project);
}

function createProject(projectName, username, success, error){
// create project
    var project = slug(projectName);
    if (project === 'admin') {
        return error();
    }
    var root = path.resolve(PROJECTS_FOLDER, project);
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
        fs.copySync(path.resolve(APP_FOLDER, 'assets/options.xml'), root + '/options.xml');
        fs.copySync(path.resolve(APP_FOLDER, 'assets/students.csv'), root + '/students.csv');
        fs.copySync(path.resolve(APP_FOLDER, 'assets/gitignore.template'), root + '/.gitignore');

        addProjectAcl(project, username);
        //create association db other are created on print
        amcCommande(null, PROJECTS_FOLDER + '/' + project, project, 'create association db', [
            'association-auto', '--data', PROJECTS_FOLDER + '/' + project + '/data',
            '--notes-id', 'etu', '--liste', PROJECTS_FOLDER + '/' + project + '/students.csv', '--liste-key', 'id'
        ], null);

        if (success) {
            success(project);
        }
    } else {
        if (error) {
            error();
        }
    }
}

app.post('/project/create', (req, res) => {
    createProject(req.body.project, req.user.username, (project) => {
        res.send(project);
    }, () => {
        res.status(403).send('Project already exists!');
    });
});

app.get('/project/:project/options', aclProject, (req, res) => {
    projectOptions(req.params.project, (err, result) => {
        acl.roleUsers(req.params.project, (err2, users) => {
            redisClient.hgetall('project:' + req.params.project + ':status', (err3, status) => {
                res.json({options: result ? result.projetAMC : {}, users: users, status: status});
            });
        });
    });
});

app.post('/project/:project/options', aclProject, (req, res) => {
    var filename = path.resolve(PROJECTS_FOLDER, req.params.project + '/options.xml');
    var builder = new xml2js.Builder();
    var xml = builder.buildObject({projetAMC: req.body.options});
    fs.writeFile(filename, xml, function(err, data) {
        if (err) {
            res.sendStatus(500);
        } else {
            ws.to(req.params.project + '-notifications').emit('update:options', req.body.options);
            commitGit(req.params.project, req.user.username, 'options');
            res.sendStatus(200);
        }
    });
});

app.post('/project/:project/copy/template', aclProject, (req, res) => {
    var TEMPLATE_FOLDER = APP_FOLDER + '/assets/templates/' + req.body.template;
    fs.copy(TEMPLATE_FOLDER + '/src', PROJECTS_FOLDER + '/' + req.params.project + '/src', (err) => {
       res.sendFile(TEMPLATE_FOLDER + '/source.tex');
    });
});

app.post('/project/:project/copy/project', aclProject, (req, res) => {
    var src = req.params.project;
    var dest = req.body.project.toLowerCase();
    createProject(dest, req.user.username, () => {
        fs.copy(PROJECTS_FOLDER + '/' + src + '/src', PROJECTS_FOLDER + '/' + dest + '/src', (err) => {
            if (err) {
                res.status(500).send('Failed to copy src files.');
            } else {
                redisClient.get('exam:' + src, (err, result) => {
                   redisClient.set('exam:' + dest, result, (err) => {
                        if (err) {
                            res.status(500).send('Failed to copy data.');
                        } else {
                            res.sendStatus(200);
                        }
                   });
                });
            }
        });
    }, () => {
        res.status(403).send('Project already exists!');
    });
});

//TODO: handle only graphics or codes needed?
app.post('/project/:project/copy/graphics', aclProject, (req, res) => {
    var src = req.params.project;
    var dest = req.body.project.toLowerCase();
    acl.hasRole(req.user.username, dest, (err, hasRole) => {
        if (hasRole && src !== dest) {
            fs.copy(PROJECTS_FOLDER + '/' + src + '/src/graphics', PROJECTS_FOLDER + '/' + dest + '/src/graphics', (err) => {
                if (err) {
                    res.status(500).send('Failed to copy src files.');
                } else {
                    res.sendStatus(200);
                }
            });
        } else {
            res.sendStatus(403);
        }
    });
});
//TODO: refactor?
app.post('/project/:project/copy/codes', aclProject, (req, res) => {
    var src = req.params.project;
    var dest = req.body.project.toLowerCase();
    acl.hasRole(req.user.username, dest, (err, hasRole) => {
        if (hasRole && src !== dest) {
            fs.copy(PROJECTS_FOLDER + '/' + src + '/src/codes', PROJECTS_FOLDER + '/' + dest + '/src/codes', (err) => {
                if (err) {
                    res.status(500).send('Failed to copy src files.');
                } else {
                    res.sendStatus(200);
                }
            });
        } else {
            res.sendStatus(403);
        }
    });
});

app.post('/project/:project/add', aclProject, (req, res) => {
    acl.addUserRoles(req.body.username, req.params.project);
    res.sendStatus(200);
});

app.post('/project/:project/remove', aclProject, (req, res) => {
    //cannot remove self
    if (req.body.username === req.user.username) {
        res.sendStatus(500);
    } else {
        acl.removeUserRoles(req.body.username, req.params.project);
        res.sendStatus(200);
    }
});

app.post('/project/:project/rename', aclProject, (req, res) => {
    let project = req.params.project;
    let newProject = slug(req.body.name);
    if ( newProject.length === 0 || newProject.indexOf('.') === 0 ) { return res.sendStatus(404); }
    //check that destination does not exists

    let newPath = PROJECTS_FOLDER + '/' + newProject;
    if (fs.existsSync(newPath)) {
        return res.sendStatus(403);
    }

    fs.rename(PROJECTS_FOLDER + '/' + project, newPath, (err) => {
        if (err) {
            return res.status(500).send(err);
        }
        redisClient.renamenx('exam:' + project, 'exam:' + newProject);
        acl.allow(newProject, '/project/' + newProject, 'admin');
        acl.roleUsers(project, (err, users: string[]) => {
            users.forEach((username) => {
                acl.removeUserRoles(username, project);
                acl.addUserRoles(username, newProject);
                redisClient.zrem('user:' + username + ':recent', project);
            });
        });
        redisClient.keys('project:' + project + ':*', function (err, keys) {
                keys.forEach(function (key) {
                    var entries = key.split(':');
                    redisClient.renamenx(key, 'project:' + newProject + ':' + entries[2]);
                });
            });
        acl.removeAllow(project, '/project/' + project, 'admin');
        acl.removeRole(project);
        acl.removeResource(project);
        res.send(newProject);
    });

});

app.post('/project/:project/delete', aclProject, (req, res) => {
    let project = req.params.project;
    if ( project.length === 0 || project.indexOf('.') === 0 ) { return res.sendStatus(404); }
    acl.roleUsers(project, (err, users: string[]) => {
        users.forEach((username) => {
            acl.removeUserRoles(username, project);
            redisClient.zrem('user:' + username + ':recent', project);
        });
        acl.removeAllow(project, '/project/' + project, 'admin');
        acl.removeRole(project);
        acl.removeResource(project);
        redisClient.del('exam:' + project);
        redisClient.keys('project:' + project + ':*', function (err, keys) {
            keys.forEach(function (key) {
                redisClient.del(key);
            });
        });
        fs.remove(PROJECTS_FOLDER + '/' + project);
    });
    res.sendStatus(200);
});

/*
archive project
zip correction/scans...
delete/recreate git
flag as archive
*/

app.get('/project/:project/gitlogs', aclProject, (req, res) => {
    var g = git(PROJECTS_FOLDER + '/' + req.params.project);
    //use cI when git version supports it
    g._run(['log', '--walk-reflogs', '--pretty=format:%H%+gs%+an%+ci'], (err, data) => {
        if (err) {
            res.status(500).send(err);
        }
        var logs = [];
        var json = data.split('\n');
        var i = 0;
        while ( i < json.length ) {
            var msg = json[i + 1];
            var idx = msg.indexOf(':');
            var log = {
                sha: json[i],
                type: msg.substring(0, idx),
                msg: msg.substring(idx + 2),
                username: json[i + 2],
                date: new Date(json[i + 3])
            };
            logs.push(log);
            i += 4;
        }
        res.json(logs);
    });
});

app.post('/project/:project/revert', aclProject, (req, res) => {
    var g = git(PROJECTS_FOLDER + '/' + req.params.project);
    g._run(['reset', '--hard', req.body.sha], (err, data) => {
        if (err) {
            ravenClient.captureException(err);
            res.status(500).send(err);
        }
        var json = path.resolve(PROJECTS_FOLDER, req.params.project + '/data.json');
        res.send(fs.readFileSync(json));
    });
});

app.get('/project/:project/zip', aclProject, (req, res) => {
    var zip = archiver('zip');
    res.on('close', function() {
        return res.sendStatus(200).end();
    });
    res.attachment(req.params.project + '.zip');
    zip.pipe(res);
    zip.directory(PROJECTS_FOLDER + '/' + req.params.project, req.params.project);
    zip.finalize();
});


app.get('/project/:project/static/:file*', aclProject, (req, res) => {
    var file = req.params.file;
    if (req.params.hasOwnProperty(0)){
        file += req.params[0];
    }
    res.sendFile(PROJECTS_FOLDER + '/' + req.params.project + '/' + file, (err) => {
        if (err && file.split('.').splice(-1)[0] === 'jpg'){
            res.sendFile(APP_FOLDER + '/assets/image_not_found.jpg');
        } else if (err) {
            res.end('NOT_FOUND');
        }
    });
});

/*
var zip = new AdmZip("./my_file.zip");
zip.extractAllTo(/target path/"/home/me/zipcontent/", /overwrite/true);
zip.addFile("test.txt", new Buffer("inner content of the file"), "entry comment goes here");
    // add local file
    zip.addLocalFile("/home/me/some_picture.png");
var willSendthis = zip.toBuffer();
*/

function makeThumb(project, filename, id, callback){
    var GRAPHICS_FOLDER = PROJECTS_FOLDER + '/' + project + '/src/graphics/';
    var convert = childProcess.spawn('convert', [
        '-trim', '+repage', '-background', 'white', '-alpha', 'remove',
        '-density', '120', filename + '[0]', id + '_thumb.jpg'
        ], {
            cwd: GRAPHICS_FOLDER
        });
    convert.on('exit', (code) => {
        if (callback){
            callback(code);
        }
    });
}

/* EDIT */
app.post('/project/:project/upload/graphics', aclProject, multipartMiddleware, (req: multiparty.Request, res) => {
    var GRAPHICS_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
    //keep extension
    var filename = req.body.id + '.' + req.files.file.name.split('.').splice(-1)[0];
    fs.copySync(req.files.file.path, GRAPHICS_FOLDER + filename);
    // don't forget to delete all req.files when done
    fs.unlinkSync(req.files.file.path);
    makeThumb(req.params.project, filename, req.body.id, (code) => {
        if (code === 0) {
            res.sendStatus(200);
        } else {
            res.sendStatus(500);
        }
    });
});

app.get('/project/:project/graphics/sync', aclProject, (req, res) => {
    var GRAPHICS_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
    var allFiles = fs.readdirSync(GRAPHICS_FOLDER);
    //remove thumbs from list
    var files = allFiles.filter((filename) => {
        return !filename.match(/(.*)_thumb.jpg/);
    });
    //get files without thumb
    files.filter((filename) => {
        return allFiles.indexOf(filename.replace(/(.*)\..*?$/, '$1_thumb.jpg')) === -1;
    })
    .forEach((filename) => {
        makeThumb(req.params.project, filename, filename.replace(/(.*)\..*?$/, '$1'), null);
    });
    res.json(files);
});


app.post('/project/:project/graphics/delete', aclProject, (req, res) => {
    var GRAPHICS_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/src/graphics/';
    try {
        fs.unlinkSync(GRAPHICS_FOLDER + req.body.id + '.' + req.body.filename.split('.').splice(-1)[0]);
        fs.unlinkSync(GRAPHICS_FOLDER + req.body.id + '_thumb.jpg');
        res.sendStatus(200);
    } catch (e) {
        res.sendStatus(500);
    }
});

function saveSourceFilesSync(project, body){
    var OUT_FOLDER = PROJECTS_FOLDER + '/' + project + '/out';
    fs.readdirSync(OUT_FOLDER).forEach((item) => {
        fs.unlinkSync(OUT_FOLDER + '/' + item);
    });

    var json = path.resolve(PROJECTS_FOLDER, project + '/data.json');
    fs.writeFileSync(json, body.json);

    var source = path.resolve(PROJECTS_FOLDER, project + '/source.tex');
    fs.writeFileSync(source, body.source);

    var questions_definition = path.resolve(PROJECTS_FOLDER, project + '/questions_definition.tex');
    fs.writeFileSync(questions_definition, body.questions_definition);

    var questions_layout = path.resolve(PROJECTS_FOLDER, project + '/questions_layout.tex');
    fs.writeFileSync(questions_layout, body.questions_layout);

    for (var id in body.codes) {
        if (body.codes.hasOwnProperty(id)) {
            var file = path.resolve(PROJECTS_FOLDER, project + '/src/codes/' + id);
            fs.writeFileSync(file, body.codes[id].content);
        }
    }
}

function commitGit(project, username, message){
    var g = git(PROJECTS_FOLDER + '/' + project);
    g.init()
    ._run(['add', '--all', '.'], (err) => {
        if (err) {
            console.log('add', err);
            ravenClient.captureException(err);
        }
    })
    ._run(['commit', '--author=' + username + ' <' + username + '@amcui.ig.he-arc.ch>', '-m', message], (err, data) => {
        if (err) {
            console.log('commit', err);
            ravenClient.captureException(err);
        }
    });
}

app.post('/project/:project/preview', aclProject, (req, res) => {
    var keyStatus = 'project:' + req.params.project + ':status';
    var keyQueue = 'project:' + req.params.project + ':previewqueue';
    var project = req.params.project;
    //replace next compile data
    redisClient.set(keyQueue, JSON.stringify(req.body), compilePreview);

    function compilePreviewEnd() {
        redisClient.hset(keyStatus, 'preview', 0);
        compilePreview();
    }

    function compilePreviewSuccess(){
        commitGit(project, req.user.username, 'preview');
        compilePreviewEnd();
    }

    function compilePreview() {
        redisClient.hgetall(keyStatus, (err, status) => {
            if (status && (status.locked > 0 || status.preview > 0)) {
                //wait
                setTimeout(compilePreview, 1000);
            } else {
                redisClient.get(keyQueue, (err, data) => {
                    if (data) {
                        redisClient.del(keyQueue);
                        var body = JSON.parse(data);
                        redisClient.hset(keyStatus, 'preview', 1);
                        //compile
                        saveSourceFilesSync(project, body);
                        amcCommande(null, PROJECTS_FOLDER + '/' + project, project, 'preview', [
                            'prepare', '--with', 'pdflatex', '--filter', 'latex',
                            '--out-corrige', 'out/out.pdf', '--mode', 'k',
                            '--n-copies', '1', 'source.tex', '--latex-stdout'
                        ], compilePreviewSuccess, compilePreviewEnd);
                    }
                });
            }
        });
    }
    res.sendStatus(200);
});

app.get('/project/:project/reset/lock', aclProject, (req, res) => {
    redisClient.hmset('project:' + req.params.project + ':status', 'locked', 0, 'preview', 0, (err) => {
        console.log(err);
    });
    res.end();
});

/* PRINT */
app.post('/project/:project/print', aclProject, (req, res) => {
    redisClient.hget('project:' + req.params.project + ':status', 'locked', (err, locked) => {
        if (err || locked === '1'){
            return res.status(409).end('ALREADY PRINTING!');
        }

        redisClient.hmset('project:' + req.params.project + ':status', 'locked', 1, 'printed', '');
        var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
        var project = req.params.project;

        saveSourceFilesSync(req.params.project, req.body);

        fs.readdirSync(PROJECT_FOLDER + 'pdf/').forEach((item) => {
            fs.unlinkSync(PROJECT_FOLDER + 'pdf/' + item);
        });

        res.sendStatus(200);

        ws.to(project + '-notifications').emit('print', {action: 'start'});


        projectOptions( req.params.project, (err, result) => {
            //sujet.pdf, catalog.pdf, calage.xy
            amcCommande(null, PROJECT_FOLDER, project, 'generating pdf', [
                'prepare', '--with', 'pdflatex', '--filter', 'latex',
                '--mode', 's[c]', '--n-copies', result.projetAMC.nombre_copies, 'source.tex',
                '--prefix', PROJECT_FOLDER, '--latex-stdout'
            ], (logCatalog) => {
                //corrige.pdf for all series
                amcCommande(null, PROJECT_FOLDER, project, 'generating answers pdf', [
                    'prepare', '--with', 'pdflatex', '--filter', 'latex',
                    '--mode', 'k', '--n-copies', result.projetAMC.nombre_copies, 'source.tex',
                    '--prefix', PROJECT_FOLDER, '--latex-stdout'
                ], (logCorrige) => {
                    //create capture and scoring db
                    amcCommande(null, PROJECT_FOLDER, project, 'computing scoring data', [
                        'prepare', '--mode', 'b', '--n-copies', result.projetAMC.nombre_copies, 'source.tex', '--prefix', PROJECT_FOLDER,
                        '--data', PROJECT_FOLDER + 'data', '--latex-stdout'
                    ], (logScoring) => {
                        //create layout
                        amcCommande(null, PROJECT_FOLDER, project, 'calculating layout', [
                            'meptex', '--src', PROJECT_FOLDER + 'calage.xy', '--data', PROJECT_FOLDER + 'data',
                             '--progression-id', 'MEP', '--progression', '1'
                        ], (logLayout) => {
                            // print
                            var params = [
                                'imprime', '--methode', 'file', '--output', PROJECT_FOLDER + 'pdf/sheet-%e.pdf',
                                '--sujet',  'sujet.pdf',  '--data',  PROJECT_FOLDER + 'data',
                                 '--progression-id', 'impression', '--progression', '1'
                            ];
                            if (result.projetAMC.split === '1') {
                                params.push('--split');
                            }
                            amcCommande(null, PROJECT_FOLDER, project, 'splitting pdf', params, (logPrint) => {
                                var pdfs = fs.readdirSync(PROJECT_FOLDER + 'pdf/').filter((item) => {
                                    return item.indexOf('.pdf') > 0;
                                });
                                commitGit(project, req.user.username, 'print');
                                redisClient.hmset('project:' + req.params.project + ':status', 'locked', 0, 'printed', new Date().getTime());
                                ws.to(project + '-notifications').emit('print', {action: 'end', pdfs: pdfs});
                            });
                        });
                    });
                });
            });
        });
    });
});

app.get('/project/:project/zip/pdf', aclProject, (req, res) => {
    var zip = archiver('zip');
    res.on('close', function() {
        return res.sendStatus(200).end();
    });
    res.attachment(req.params.project + '.zip');
    zip.pipe(res);
    zip.directory(PROJECTS_FOLDER + '/' + req.params.project + '/pdf', 'sujets');
    zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/catalog.pdf', {name: 'catalog.pdf'});
    zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/corrige.pdf', {name: 'corrige.pdf'});
    zip.file(PROJECTS_FOLDER + '/' + req.params.project + '/calage.xy', {name: 'calage.xy'});
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

app.post('/project/:project/upload', aclProject, multipartMiddleware, (req: multiparty.Request, res) => {
    var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
    var project = req.params.project;
    fs.copySync(req.files.file.path, path.resolve(PROJECTS_FOLDER, req.params.project, 'scans/', req.files.file.name));
    // don't forget to delete all req.files when done
    fs.unlinkSync(req.files.file.path);
    tmp.file((err, path, fd, cleanup) => {
        fs.writeFileSync(path, 'scans/' + req.files.file.name);
        //need to call getimage with file to get path of extracted files...
        amcCommande(res, PROJECT_FOLDER, project, 'extracting images', [
            'getimages', '--progression-id', 'getimages', '--progression', '1', '--vector-density', '250', '--orientation', 'portrait', '--list', path
        ], (logImages) => {
            projectOptions( req.params.project, (err, result) => {
                var params = [
                    'analyse', '--tol-marque', '0.2,0.2', '--prop', '0.8', '--bw-threshold', '0.6', '--progression-id', 'analyse', '--progression', '1',
                    '--n-procs', '1', '--projet', PROJECT_FOLDER, '--liste-fichiers',  path
                ];
                if (result.projetAMC.auto_capture_mode === '1') {
                    params.push('--multiple');
                }
                amcCommande(res, PROJECT_FOLDER, project, 'analysing image', params, (logAnalyse) => {
                    redisClient.hset('project:' + project + ':status', 'scanned', new Date().getTime());
                    res.json({
                        logImages: logImages,
                        logAnalyse: logAnalyse
                    });
                });
            });
        });
    });
});

app.get('/project/:project/missing', aclProject, (req, res) => {
    database(req, res, (db) => {
        //TODO in future check that role=1 version>1.2.1
        var query = 'SELECT a.student as student, a.page as page, a.copy as copy, ok.page IS NULL as missing '
        + 'FROM (SELECT enter.student, enter.page, p.copy FROM ( '
        + '    SELECT student, page '
        + '    FROM layout_namefield '
        + '    UNION '
        + '    SELECT student, page '
        + '    FROM layout_box) enter, '
        + '    (SELECT student, copy FROM capture_page GROUP BY student, copy) p'
        + '  WHERE p.student = enter.student) a '
        + 'LEFT JOIN capture_page ok ON a.student = ok.student AND a.page = ok.page AND ok.copy = a.copy '
        + 'ORDER BY student, copy, page';

        db('all', query, (rows) => {
            var seenTotal = [];
            var seenMissing = [];
            if (!rows) {
                rows = [];
            }
            var results = rows.reduce((result, page) => {
                var id = page.student + '_' + page.copy;
                if (seenTotal.indexOf(id) < 0){
                  result.complete += 1;
                  seenTotal.push(id);
                }
                if (page.missing === 1){
                  result.missing.push(page);
                  if (seenMissing.indexOf(id) < 0){
                    result.complete -= 1;
                    result.incomplete += 1;
                    seenMissing.push(id);
                  }
                }
                return result;
            }, {complete: 0, incomplete: 0, missing: []});

            var query2 = 'SELECT * FROM capture_failed';
            db('all', query2, (rows) => {
                results.failed = rows;
                res.json(results);
            });
        });
    });
});


app.get('/project/:project/capture', aclProject, (req, res) => {
    projectThreshold(req.params.project, (err, threshold) => {
        database(req, res, (db) => {
            var query = "SELECT p.student || '/' || p.page || ':' || p.copy as id, p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, "
            + '(SELECT ROUND(10* COALESCE(($threshold - MIN(ABS(1.0*black/total - $threshold)))/ $threshold, 0), 1) '
            + 'FROM capture_zone WHERE student=p.student AND page=p.page AND copy=p.copy AND type=4) s '
            + 'FROM capture_page p ORDER BY p.student, p.page, p.copy';

            db('all', query, {$threshold: threshold}, (rows) => {
                res.json(rows || []);
            });
        });
    });
});

app.get('/project/:project/capture/:student/:page\::copy', aclProject, (req, res) => {
    database(req, res, (db) => {
        var query = 'SELECT c.src, c.student, c.page, c.copy, c.timestamp_auto, c.timestamp_manual, c.a, c.b, c.c, c.d, c.e, c.f, '
        + 'c.mse, c.layout_image, l.dpi, l.width as originalwidth, l.width, l.height as originalheight, l.height FROM capture_page c JOIN layout_page l ON c.student = l.student AND c.page = l.page WHERE c.student=$student AND c.page=$page AND c.copy=$copy';
        db('get', query, {$student: req.params.student, $page: req.params.page, $copy: req.params.copy}, (row) => {
            if (row) {
                sizeOf(PROJECTS_FOLDER + '/' + req.params.project + '/cr/' + row.layout_image, function (err, dimensions) {
                    row.ratiox = 1;
                    row.ratioy = 1;
                    if (dimensions) {
                        row.ratiox = row.width / dimensions.width;
                        row.ratioy = row.height / dimensions.height;
                        row.width = dimensions.width;
                        row.height = dimensions.height;
                    }
                    res.json(row);
                });
            } else {
                res.sendStatus(404);
            }
        });
    });
});

app.post('/project/:project/capture/setauto', aclProject, (req, res) => {
    database(req, res, (db) => {
        var query = 'UPDATE capture_page SET timestamp_annotate=0, timestamp_manual=0 WHERE student=$student AND page=$page AND copy=$copy';
        db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
            query = 'UPDATE capture_zone SET manual=-1 WHERE student=$student AND page=$page AND copy=$copy';
            db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
                redisClient.hset('project:' + req.params.project + ':status', 'scanned', new Date().getTime());
                res.sendStatus(200);
            });
        });
    });
});

/* TODO: support insert for fully manual pages */
app.post('/project/:project/capture/setmanual', aclProject, (req, res) => {
    database(req, res, (db) => {
        var query = "UPDATE capture_page SET timestamp_annotate=0, timestamp_manual=strftime('%s','now') WHERE student=$student AND page=$page AND copy=$copy";
        db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
            query = 'UPDATE capture_zone SET manual=$manual WHERE student=$student AND page=$page AND copy=$copy AND type=$type AND id_a=$id_a AND id_b=$id_b';
            db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy, $manual: req.body.manual, $type: req.body.type, $id_a: req.body.id_a, $id_b: req.body.id_b}, () => {
                redisClient.hset('project:' + req.params.project + ':status', 'scanned', new Date().getTime());
                res.sendStatus(200);
            });
        });
    });
});

app.post('/project/:project/capture/delete', aclProject, (req, res) => {
	/*
	1) get image files generated, and remove them
    scan file, layout image, in cr directory, annotated scan, zooms
    */
    database(req, res, (db) => {

        var query = "SELECT replace(src, '%PROJET/', '') as path FROM capture_page "
        + 'WHERE student=$student AND page=$page AND copy=$copy '
        + 'UNION '
        + "SELECT 'cr/' || layout_image FROM capture_page "
        + 'WHERE student=$student AND page=$page AND copy=$copy '
        + 'UNION '
        + "SELECT 'cr/corrections/jpg/' || annotated FROM capture_page "
        + 'WHERE student=$student AND page=$page AND copy=$copy '
        + 'UNION '
        + "SELECT 'cr/' || image FROM capture_zone "
        + 'WHERE student=$student AND page=$page AND copy=$copy AND image IS NOT NULL';
        db('all', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, (rows) => {
            rows.forEach((row) => {
                fs.unlink( PROJECTS_FOLDER + '/' + req.params.project + '/' + row.path, (err) => {
                    console.log(err);
                });
            });
            // 2) remove data from database
            db('run', 'DELETE FROM capture_position WHERE zoneid IN (SELECT zoneid FROM capture_zone WHERE student=$student AND page=$page AND copy=$copy)',
            {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
                db('run', 'DELETE FROM capture_zone WHERE student=$student AND page=$page AND copy=$copy',
                {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
                    db('run', 'DELETE FROM capture_page WHERE student=$student AND page=$page AND copy=$copy',
                    {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
                        db('run', 'DELETE FROM scoring_score WHERE student=$student AND copy=$copy',
                        {$student: req.body.student, $copy: req.body.copy}, () => {
                            db('run', 'DELETE FROM scoring_mark WHERE student=$student AND copy=$copy',
                            {$student: req.body.student, $copy: req.body.copy}, () => {
                                db('run', 'DELETE FROM scoring_code WHERE student=$student AND copy=$copy',
                                {$student: req.body.student, $copy: req.body.copy}, () => {
                                    db('run', 'DELETE FROM association_association WHERE student=$student AND copy=$copy',
                                    {$student: req.body.student, $copy: req.body.copy}, () => {
                                        redisClient.hset('project:' + req.params.project + ':status', 'scanned', new Date().getTime());
                                        res.sendStatus(200);
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

/* ZONES */

app.get('/project/:project/zones/:student/:page\::copy', aclProject, (req, res) => {
    database(req, res, (db) => {
        var query = 'SELECT z.id_a AS question, z.id_b AS answer, z.total, z.black, '
        + 'z.manual, max(CASE WHEN p.corner = 1 THEN p.x END) as x0, '
        + 'max(CASE WHEN p.corner = 1 THEN p.y END) as y0, '
        + 'max(CASE WHEN p.corner = 2 THEN p.x END) as x1, '
        + 'max(CASE WHEN p.corner = 2 THEN p.y END) as y1, '
        + 'max(CASE WHEN p.corner = 3 THEN p.x END) as x2, '
        + 'max(CASE WHEN p.corner = 3 THEN p.y END) as y2, '
        + 'max(CASE WHEN p.corner = 4 THEN p.x END) as x3, '
        + 'max(CASE WHEN p.corner = 4 THEN p.y END) as y3 '
        + 'FROM capture_zone AS z '
        + 'JOIN capture_position as p ON z.zoneid=p.zoneid '
        + 'WHERE z.student=$student AND z.page=$page AND z.copy=$copy AND z.type=4 AND p.type=1 '
        + 'GROUP BY z.zoneid, z.id_a, z.id_b, z.total, z.black, z.manual '
        + 'ORDER BY min(p.y), min(p.y)';
        db('all', query, {$student: req.params.student, $page: req.params.page, $copy: req.params.copy}, (rows) => {
            res.json(rows);
        });
    });
});

/* GRADES */

app.get('/project/:project/scoring', aclProject, (req, res) => {
    var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
    var project = req.params.project;

    projectOptions( req.params.project, (err, result) => {
        amcCommande(null, PROJECT_FOLDER, project, 'computing scoring data', [
            'prepare', '--mode', 'b', '--n-copies', result.projetAMC.nombre_copies, 'source.tex', '--prefix', PROJECT_FOLDER,
            '--data', PROJECT_FOLDER + 'data', '--latex-stdout'
        ], (logScoring) => {
            res.json(logScoring);
        });
    });
});

app.post('/project/:project/csv', aclProject, (req, res) => {
    var filename = path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv');
    fs.writeFile(filename, req.body, function(err, data) {
        if (err) {
            res.sendStatus(500).end();
            return;
        } else {
            //try auto-match
            //TODO get 'etu' from scoring_code?
            amcCommande(res, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'matching students', [
                'association-auto', '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data',
                '--notes-id', 'etu', '--liste', filename, '--liste-key', 'id'
            ], (log) => {
                res.json({log: log});
            });
        }
    });
});

app.get('/project/:project/csv', aclProject, (req, res) => {
    userSaveVisit(req.user.username, req.params.project);
    res.sendFile(path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv'));
});

app.get('/project/:project/gradefiles', aclProject, (req, res) => {
    redisClient.get('project:' + req.params.project + ':gradefiles', (err, data) => {
        if (data) {
            res.send(data);
        } else {
            res.send([]);
        }
    });
});

app.post('/project/:project/gradefiles', aclProject, (req, res) => {
    redisClient.set('project:' + req.params.project + ':gradefiles',  JSON.stringify(req.body));
    res.sendStatus(200);
});

//could do in db directly?
app.post('/project/:project/association/manual', aclProject, (req, res) => {
     amcCommande(res, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'matching students', [
        'association', '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data',
        '--set', '--student', req.body.student, '--copy', req.body.copy, '--id', req.body.id
    ], (log) => {
        res.json({log: log});
    });
});


app.get('/project/:project/names', aclProject, (req, res) => {
    // LIST OF STUDENTS with their name field and if matched
    database(req, res, (db) => {
        var query = 'SELECT p.student, p.page, p.copy, z.image, a.manual, a.auto '
            + 'FROM capture_page p JOIN layout.layout_namefield l ON p.student=l.student AND p.page = l.page '
            + 'LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy '
            + 'LEFT JOIN assoc.association_association a ON a.student = p.student AND a.copy = p.copy';

        db('all', query, (rows) => {
            res.json(rows);
        });
    });
});

function calculateMarks(project, callback){
    var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + project + '/';
    projectThreshold(project, (err, threshold) => {
        amcCommande(null, PROJECT_FOLDER, project, 'calculating marks', [
            'note', '--data', PROJECT_FOLDER + 'data', '--seuil', threshold, '--progression-id', 'notation', '--progression', '1'
            ], (log) => {
                redisClient.hset('project:' + project + ':status', 'marked', new Date().getTime());
                if (callback) {
                    callback(log);
                }
        });
    });
}


app.get('/project/:project/mark', aclProject, (req, res) => {
    calculateMarks(req.params.project, (log) => {
        res.json(log);
    });
});

app.get('/project/:project/scores', aclProject, (req, res) => {

    function getScores(){
        database(req, res, (db) => {
            var query = 'SELECT COALESCE(aa.manual, aa.auto) AS id, ss.*, st.title, lb.page '
                + 'FROM scoring_score ss '
                + 'JOIN scoring_title st ON ss.question = st.question '
                + 'JOIN scoring_question sq ON ss.question = sq.question AND '
                + 'ss.student = sq.student AND sq.indicative = 0 '
                + 'LEFT JOIN association_association aa ON aa.student = ss.student AND aa.copy = ss.copy '
                + 'LEFT JOIN (SELECT student, page, question FROM layout_box GROUP BY student, page, question) lb ON lb.student = ss.student AND lb.question = ss.question '
                + 'ORDER BY id, student, copy, title';

            db('all', query, (rows) => {
                res.json(rows);
            });
        });
    }

    //check if we need to update markings
    redisClient.hmget('project:' + req.params.project + ':status', 'scanned', 'marked', (err, results) => {
        if (results[0] > results[1]) {
            calculateMarks(req.params.project, getScores);
        } else {
            getScores();
        }
    });
});


/* REPORT */

app.get('/project/:project/ods', aclProject, (req, res) => {
    var filename = path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv');
    var exportFile = path.resolve(PROJECTS_FOLDER, req.params.project + '/exports/export.ods');
    amcCommande(res, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'generating ods', [
        'export', '--module', 'ods', '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data', '--useall', '1', '--sort', 'l',
        '--fich-noms', filename, '--output', exportFile, '--option-out', 'nom=' + req.params.project,
        '--option-out', 'groupsums=1', '--option-out', 'stats=1', '--option-out', 'columns=student.copy,student.key,student.name', '--option-out', 'statsindic=1'
    ], (log) => {
        res.attachment('export.ods');
        res.sendFile(exportFile);
    });
});


/*
ANNOTATE

*/

app.post('/project/:project/annotate', aclProject, (req, res) => {
    redisClient.hget('project:' + req.params.project + ':status', 'locked', (err, locked) => {
        if (locked === '1'){
            return res.status(409).end('ALREADY WORKING!');
        }
        res.sendStatus(200);
        ws.to(req.params.project + '-notifications').emit('annotate', {action: 'start'});
        redisClient.hmset('project:' + req.params.project + ':status', 'locked', 1, 'annotated', '');
        projectOptions( req.params.project, (err, result) => {
            tmp.file((err, tmpFile, fd, cleanup) => {
                var filename = path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv');

                var symbols = '0-0:' + result.projetAMC.symbole_0_0_type + '/' + result.projetAMC.symbole_0_0_color
                + ',0-1:' + result.projetAMC.symbole_0_1_type + '/' + result.projetAMC.symbole_0_1_color
                + ',1-0:' + result.projetAMC.symbole_1_0_type + '/' + result.projetAMC.symbole_1_0_color
                + ',1-1:' + result.projetAMC.symbole_1_1_type + '/' + result.projetAMC.symbole_1_1_color;

                var params = [
                    'annote', '--progression-id', 'annote', '--progression', '1', '--cr',  PROJECTS_FOLDER + '/' + req.params.project + '/cr',
                    '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data/',
                    '--ch-sign', '2', '--taille-max', '1000x1500', '--qualite', '100', '--line-width', '2',
                    '--symbols', symbols,
                    '--position', result.projetAMC.annote_position, '--pointsize-nl', '60', '--verdict', result.projetAMC.verdict,
                    '--verdict-question', result.projetAMC.verdict_q,
                    '--fich-noms', filename,
                    '--no-changes-only',
                    '--ecart-marge', result.projetAMC.annote_ecart_marge || '2'];
                if (req.body.ids) {
                    req.body.ids.forEach((id) => {
                        fs.writeFileSync(tmpFile, id);
                    });
                    params.push('--id-file');
                    params.push(tmpFile);
                } else {
                    // annotate all but clear folder first
                    fs.emptyDir(PROJECTS_FOLDER + '/' + req.params.project + '/cr/corrections/pdf');
                }
                amcCommande(null, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'annotating pages', params, (logAnnote) => {
                    params = [
                        'regroupe', '--no-compose', '--projet', PROJECTS_FOLDER + '/' + req.params.project,
                        '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data',
                        '--sujet', PROJECTS_FOLDER + '/' + req.params.project + '/sujet.pdf',
                        '--progression-id', 'regroupe', '--progression', '1',
                        '--modele', result.projetAMC.modele_regroupement || '(ID)',
                        '--fich-noms', filename, '--register', '--no-rename'
                    ];
                    if (req.body.ids) {
                        params.push('--id-file');
                        params.push(tmpFile);
                    }
                    amcCommande(null, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'creating annotated pdf', params, (logRegroupe) => {
                        cleanup();
                        commitGit(req.params.project, req.user.username, 'annotate');
                        redisClient.hmset('project:' + req.params.project + ':status', 'locked', 0, 'annotated', new Date().getTime());
                        var found = logRegroupe.match(/(cr\/.*?\.pdf)/);
                        ws.to(req.params.project + '-notifications').emit('annotate', {action: 'end', type: req.body.ids ? 'single' : 'all', file: found ? found[1] : undefined});
                        /*
                        res.json({
                            logAnnote: logAnnote,
                            logRegroupe: logRegroupe
                        });
                        */
                    });
                });
            });
        });
    });
});

app.get('/project/:project/zip/annotate', aclProject, (req, res) => {
    var zip = archiver('zip');
    res.on('close', function() {
        return res.sendStatus(200).end();
    });
    res.attachment(req.params.project + '_annotate.zip');
    zip.pipe(res);
    zip.directory(PROJECTS_FOLDER + '/' + req.params.project + '/cr/corrections/pdf', 'annotate');
    zip.file(APP_FOLDER + '/assets/extractFirstPage.bat', {name: 'extractFirstPage.bat.txt'});
    zip.finalize();
});
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
        var query = "SELECT value FROM scoring.scoring_variables WHERE name='darkness_threshold'";
        db('get', query, (setting) => {
            var threshold = 0.5; //TODO change?
            if (setting && setting.value){
                threshold = setting.value;
            }
            database(req, res, (db) => {
                query = 'SELECT t.question, t.title, q.indicative, q.type, s.max, AVG(s.score) / s.max AS avg '
                    + 'FROM scoring.scoring_title t JOIN scoring.scoring_question q ON  t.question = q.question '
                    + 'LEFT JOIN scoring.scoring_score s ON s.question = t.question '
                    + "WHERE q.strategy <> 'auto=0' "
                    + 'GROUP BY t.question, t.title, q.indicative, q.type, s.max '
                    + 'ORDER BY t.question';

                db('all', query, (questionsList) => {
                    var questions = {};
                    questionsList.forEach((question) => {
                        question.answers = [];
                        questions[question.question] = question;
                    });
                    database(req, res, (db) => {
                        query = "SELECT question, 'all' AS answer, COUNT(*) AS nb, "
                            + '0 as correct '
                            + 'FROM scoring.scoring_score '
                            + 'GROUP BY question '
                            + 'UNION '
                            + "SELECT question, 'invalid' AS answer, COUNT(*)-COUNT(NULLIF(why,'E')) AS nb, "
                            + '3 as correct '
                            + 'FROM scoring.scoring_score '
                            + 'GROUP BY question '
                            + 'UNION '
                            + "SELECT question, 'empty' AS answer, COUNT(*)-COUNT(NULLIF(why,'V')) AS nb, "
                            + '2 as correct '
                            + 'FROM scoring.scoring_score '
                            + 'GROUP BY question '
                            + 'UNION '
                            + 'SELECT s.question AS question, z.id_b AS answer, '
                            + 'SUM(CASE '
                            + "WHEN s.why='V' THEN 0 "
                            + "WHEN s.why='E' THEN 0 "
                            + 'WHEN z.manual >= 0 THEN z.manual '
                            + 'WHEN z.total<=0 THEN 0 '
                            + 'WHEN z.black >= $threshold * z.total THEN 1 '
                            + 'ELSE 0 '
                            + 'END) AS nb, a.correct AS correct '
                            + 'FROM capture_zone z JOIN scoring.scoring_score s '
                            + 'ON z.student = s.student AND '
                            + 'z.copy = s.copy AND '
                            + 's.question = z.id_a '
                            + 'AND z.type = 4 '
                            + 'JOIN scoring.scoring_answer a ON a.student = s.student '
                            + 'AND a.question = s.question '
                            + 'AND z.id_b = a.answer '
                            + 'GROUP BY z.id_a, z.id_b, a.correct';

                        db('all', query, {$threshold: threshold}, (rows) => {
                            rows.forEach((row) => {
                                if (questions[row.question]){
                                    if (row.answer === 'all'){
                                        questions[row.question].total = row.nb;
                                    } else {
                                        questions[row.question].answers.push(row);
                                    }
                                }
                            });
                            res.json(questionsList.map((q) => {
                                return questions[q.question];
                            }));
                        });
                    });
                });
            });
        });
    });
});


//for acl middlware we have to handle its custom httperror
app.use(<express, ErrorRequestHandler>(err, req, res, next) => {
    // Move on if everything is alright
    if (!err) {
        return next();
    }
    // Something is wrong, inform user
    if (err.errorCode && err.msg) {
        console.log('custom_error_handler:', err.errorCode, err.msg);
        res.status(err.errorCode).json( err.msg );
    } else {
        console.log('custom_error_handler_skip:', err);
        next(err);
    }
});

app.use(raven.middleware.express.errorHandler(process.env.SENTRY_DSN));

if (env === 'development') {
    app.use(errorHandler({log: true}));
}

server.listen(process.env.SERVER_PORT, '0.0.0.0');
server.on('listening', function(){
    console.log('server listening on port %d in %s mode', server.address().port, app.settings.env);
});

export var App = app;
