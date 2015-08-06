///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
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
//import AdmZip = require('adm-zip');
import archiver = require('archiver');
import diffSync= require('diffsync');
import redisDataAdapter = require('./diffsyncredis');

var multipartMiddleware = multiparty();

var APP_FOLDER = path.resolve(__dirname, '../app/');
var PROJECTS_FOLDER = path.resolve(__dirname, '../projects/');

var redisClient = redis.createClient(process.env.REDIS_PORT_6379_TCP_PORT, process.env.REDIS_PORT_6379_TCP_ADDR, {});
redisClient.on('error', function (err) {
    console.log('Redis error ' + err);
});
var acl = new Acl(new Acl.redisBackend(redisClient, 'acl')
/*
    , {debug: (txt) => {
    console.log(JSON.stringify(txt));
}}
*/);


var app = express();
var server = require('http').Server(app);
var ws = io(server);


ws.use(socketioJwt.authorize({
    secret: process.env.JWT_SECRET,
    timeout: 15000, // 15 seconds to send the authentication message
    handshake: true
}));

//in memory rooms users list
var rooms = {};

ws.on('connection', (socket) => {
    //this socket is authenticated, we are good to handle more events from it.
    var username = (<any>socket).decoded_token.username;
    socket.on('listen', (project) => {
        acl.hasRole(username, project, (err, hasRole) => {
            if (!hasRole) {
                socket.disconnect(true);
            } else {
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
console.log(diffSyncServer);

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

//secure /project with auth api
app.use('/project', expressJwt({
    secret: process.env.JWT_SECRET,
    getToken: function fromHeaderOrQuerystring (req) {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.query && req.query.token) {
            return req.query.token;
        }
        return null;
    }
}));

function aclProject(req, res, next){
    return <express.RequestHandler>acl.middleware(2, (req: express.Request, res) => {
        return req.user.username;
    }, 'admin')(req, res, next);
}


function database(req, res, callback){
    var project = req.params.project;
    var db = new sqlite3.Database('app/projects/' + project + '/data/capture.sqlite', (err) => {
        if (err){
            res.status(500).end(JSON.stringify(err));
            return;
        }
        db.exec("ATTACH DATABASE 'app/projects/" + project + "/data/layout.sqlite' AS layout", () => {
            db.exec("ATTACH DATABASE 'app/projects/" + project + "/data/association.sqlite' AS assoc", () => {
                db.exec("ATTACH DATABASE 'app/projects/" + project + "/data/scoring.sqlite' AS scoring", () => {
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
            callback(log);
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
    if (req.body.password && req.body.username) {
        var username = req.body.username.toLowerCase();
        var sendToken = (user) => {
            try {
                delete user.password;
                var token = jwt.sign(user, process.env.JWT_SECRET, {expiresInMinutes: 60 * 6});
                res.json({token: token});
            } catch (e) {
                console.log(e);
                res.status(500).send(e);
            }
        };
        redisClient.get('user:' + username, function(err, reply) {
            if (reply) {
                var user = JSON.parse(reply);
                if (bcrypt.compareSync(req.body.password, user.password)) {
                    sendToken(user);
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

app.get('/project/list', (req, res) => {
    acl.userRoles(req.user.username, (err, roles) => {
        var projects = [];
        roles.forEach((role, idx) => {
            redisClient.hgetall('project:' + role + ':status', (err2, status) => {
                projects.push({project: role, status: status});
                if (projects.length === roles.length){
                    res.json(projects);
                }
            });
        });
    });
});


function createProject(projectName, username, success, error){
// create project
    var project = projectName.toLowerCase();
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
        //role, resource, permission
        acl.allow(project, '/project/' + project, 'admin');
        //user, role
        acl.addUserRoles(username, project);
        if (success) {
            success();
        }
    } else {
        if (error) {
            error();
        }
    }
}

app.post('/project/create', (req, res) => {
    createProject(req.body.project, req.user.username, () => {
        res.sendStatus(200);
    }, () => {
        res.status(403).send('Project already exists!');
    });
});

app.get('/project/:project/options', aclProject, (req, res) => {
    projectOptions(req.params.project, (err, result) => {
        acl.roleUsers(req.params.project, (err2, users) => {
            redisClient.hgetall('project:' + req.params.project + ':status', (err3, status) => {
                res.json({options: result.projetAMC, users: users, status: status});
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
        '-density', '120', filename + '[0]', id + '_thumb.jpg'
        ], {
            cwd: GRAPHICS_FOLDER
        });
    convert.on('close', (code) => {
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
                        ], compilePreviewEnd, compilePreviewEnd);
                    }
                });
            }
        });
    }
    res.sendStatus(200);
});

app.get('/project/:project/reset/lock', aclProject, (req, res) => {
    redisClient.hmset('project:' + req.params.project + ':status', 'locked', 0, 'preview', 0);
    res.end();
});

/* PRINT */
app.post('/project/:project/print', aclProject, (req, res) => {
    redisClient.hget('project:' + req.params.project + ':status', 'locked', (err, locked) => {
        if (locked === '1'){
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
                        'prepare', '--mode', 'b', 'source.tex', '--prefix', PROJECT_FOLDER,
                        '--data', PROJECT_FOLDER + 'data', '--latex-stdout'
                    ], (logScoring) => {
                        //create layout
                        amcCommande(null, PROJECT_FOLDER, project, 'calculating layout', [
                            'meptex', '--src', PROJECT_FOLDER + 'calage.xy', '--data', PROJECT_FOLDER + 'data',
                             '--progression-id', 'MEP', '--progression', '1'
                        ], (logLayout) => {
                            // print
                            //TODO optional split answer --split
                            amcCommande(null, PROJECT_FOLDER, project, 'splitting pdf', [
                                'imprime', '--methode', 'file', '--output', PROJECT_FOLDER + 'pdf/sheet-%e.pdf',
                                '--sujet',  'sujet.pdf',  '--data',  PROJECT_FOLDER + 'data',
                                 '--progression-id', 'impression', '--progression', '1'
                            ], (logPrint) => {
                                var pdfs = fs.readdirSync(PROJECT_FOLDER + 'pdf/').filter((item) => {
                                    return item.indexOf('.pdf') > 0;
                                });
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
            var params = [
                'analyse', '--tol-marque', '0.2,0.2', '--prop', '0.8', '--bw-threshold', '0.6', '--progression-id', 'analyse', '--progression', '1',
                '--n-procs', '0', '--projet', PROJECT_FOLDER, '--liste-fichiers',  path
            ];
            //TODO --multiple //if copies
            amcCommande(res, PROJECT_FOLDER, project, 'analysing image', params, (logAnalyse) => {
                res.json({
                    logImages: logImages,
                    logAnalyse: logAnalyse
                });
            });
        });
    });
});

app.get('/project/:project/mark', aclProject, (req, res) => {
    var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';
    projectThreshold(req.params.project, (err, threshold) => {
        amcCommande(res, PROJECT_FOLDER, req.params.project, 'calculating marks', [
            'note', '--data', PROJECT_FOLDER + 'data', '--seuil', threshold, '--progression-id', 'notation', '--progression', '1'
            ], (log) => {
                res.json({log: log});
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
                var id = page.student + page.copy;
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
        var query = 'SELECT * FROM capture_page WHERE student=$student AND page=$page AND copy=$copy';
        db('get', query, {$student: req.params.student, $page: req.params.page, $copy: req.params.copy}, (row) => {
            res.json(row);
        });
    });
});

app.post('/project/:project/capture/setauto', aclProject, (req, res) => {
    database(req, res, (db) => {
        var query = 'UPDATE capture_page SET timestamp_annotate=0, timestamp_manual=-1 WHERE student=$student AND page=$page AND copy=$copy';
        db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
            query = 'UPDATE capture_zone SET manual=-1 WHERE student=$student AND page=$page AND copy=$copy';
            db('run', query, {$student: req.body.student, $page: req.body.page, $copy: req.body.copy}, () => {
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
    res.sendFile(path.resolve(PROJECTS_FOLDER, req.params.project + '/students.csv'));
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


app.get('/project/:project/scores', aclProject, (req, res) => {
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
                var params = [
                    'annote', '--progression-id', 'annote', '--progression', '1', '--cr',  PROJECTS_FOLDER + '/' + req.params.project + '/cr',
                    '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data/',
                    '--ch-sign', '2', '--taille-max', '1000x1500', '--qualite', '100', '--line-width', '2',
                    '--symbols', '0-0:none/#000000000000,0-1:mark/#ffff00000000,1-0:circle/#ffff00000000,1-1:circle/#0000ffff26ec',  /* TODO: from option */
                    '--position', 'marge', '--pointsize-nl', '60', '--verdict', result.projetAMC.verdict,
                    '--verdict-question', result.projetAMC.verdict_q,
                    '--fich-noms', filename,
                    '--no-changes-only',
                    '--ecart-marge', '2'];
                if (req.body.ids) {
                    req.body.ids.forEach((id) => {
                        fs.writeFileSync(tmpFile, id);
                    });
                    params.push('--id-file');
                    params.push(tmpFile);
                }
                amcCommande(null, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'annotating pages', params, (logAnnote) => {
                    params = [
                        'regroupe', '--no-compose', '--projet', PROJECTS_FOLDER + '/' + req.params.project,
                        '--data', PROJECTS_FOLDER + '/' + req.params.project + '/data',
                        '--sujet', PROJECTS_FOLDER + '/' + req.params.project + '/sujet.pdf',
                        '--progression-id', 'regroupe', '--progression', '1',
                        '--modele', '(name)', /* TODO: from option */
                        '--fich-noms', filename, '--register --no-rename'
                    ];
                    if (req.body.ids) {
                        params.push('--id-file');
                        params.push(tmpFile);
                    }
                    amcCommande(null, PROJECTS_FOLDER + '/' + req.params.project, req.params.project, 'creating annotated pdf', params, (logRegroupe) => {
                        cleanup();
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
    zip.finalize();
});
/*

(N)
is replaced by the student's name.
(ID)
is replaced by the student number.
(COL)

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
        res.status(err.errorCode).json( err.msg );
    } else {
        next(err);
    }
});

if (env === 'development') {
    app.use(errorHandler({ dumpExceptions: true, showStack: true }));
}

server.listen(process.env.SERVER_PORT, '0.0.0.0');
server.on('listening', function(){
    console.log('server listening on port %d in %s mode', server.address().port, app.settings.env);
});

export var App = app;
