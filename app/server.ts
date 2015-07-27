///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
import fs = require('fs-extra');
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
var multipartMiddleware = multiparty();

var APP_FOLDER = path.resolve(__dirname, '../app/');
var PROJECTS_FOLDER = path.resolve(__dirname, '../app/projects/');

var redisClient = redis.createClient(process.env.REDIS_PORT_6379_TCP_PORT, process.env.REDIS_PORT_6379_TCP_ADDR, {});
redisClient.on('error', function (err) {
    console.log('Redis error ' + err);
});
var acl = new Acl(new Acl.redisBackend(redisClient, 'acl'), {debug: (txt) => {
    console.log(JSON.stringify(txt));
}});

var app = express();
var server = require('http').Server(app);
var ws = io(server);

var env = process.env.NODE_ENV || 'development';
if (env === 'development') {
    sqlite3.verbose();
    //app.use(express.static(__dirname + '/../../avionmake/app'));
    //app.use('/scripts', express.static(__dirname + '/../../avionmake/.tmp/scripts'));
    //app.use('/styles', express.static(__dirname + '/../../avionmake/.tmp/styles'));
    //app.use('/bower_components', express.static(__dirname + '/../../avionmake/bower_components'));
}
else if (env === 'production') {
    app.use(express.static(__dirname + '/public'));
}

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit: '50mb'}));

ws.on('connection', socketioJwt.authorize({
    secret: process.env.JWT_SECRET,
    timeout: 15000 // 15 seconds to send the authentication message
  }));

ws.on('authenticated', function(socket) {
    //this socket is authenticated, we are good to handle more events from it.
    console.log('hello! ' + socket.decoded_token.id);
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
/*
                        var tryDBCall = () => {
                            try {

                            } catch (e) {
                                console.log('ERROR.TEST', e);
                                if (e.name === 'SQLITE_BUSY'){
                                    setTimeout(tryDBCall, 1000);
                                } else {
                                    throw e;
                                }
                            }
                        };
                        tryDBCall();
*/

                    };
                    callback(dbHandled);
                });
            });
        });
    });
}

/* TEST AREA */
app.get('/', (req, res) => {
    res.send('Hello World3!');
});

app.get('/project/test', (req, res) => {
    acl.allowedPermissions(req.user.username, 'test5', (err, roles) => {
        res.send('Hello secure! #' + req.user.username + JSON.stringify(roles)  + JSON.stringify(err));
    });

});

app.get('/project/:project/info', aclProject, (req, res) => {
        res.send('Your project! #' + req.user.username);
});

/*
Change options of a project
	-> some trigger other functions? (marks, annotations)

Upload a project?

Edit Latex
	-> recompute markings?

Preview Latex

Print
   ->before check layout (user interaction?)

Upload scans

Get capture data state

Upload students
	-> auto map students
Manual map students

Display marks & question reports

save formulas
save custom csv data

annotate
	-> auto export current grade selection
	-> options preview annotations on 1 copy
	-> reset and full annotate
export /download pdfs

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
        res.json(roles);
    });
});

app.post('/project/create', (req, res) => {
    // create project
    var project = req.body.project;
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
        mkdirp.sync(root + '/src');
        //copy default option file
        fs.copySync(path.resolve(APP_FOLDER, 'assets/options.xml'), root + '/options.xml');
        //role, resource, permission
        acl.allow(project, '/project/' + project, 'admin');
        //user, role
        acl.addUserRoles(req.user.username, project);
        res.sendStatus(200);
    }else{
        res.status(403).send('Project already exists!');
    }
});

app.get('/project/:project/options', aclProject, (req, res) => {
    var filename = path.resolve(PROJECTS_FOLDER, req.params.project + '/options.xml');
    fs.readFile(filename, 'utf-8', function(err, data) {
        xml2js.parseString(data, {explicitArray: false}, function (err, result) {
            acl.roleUsers(req.params.project, (err, users) => {
                res.json({options: result.projetAMC, users: users});
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

app.post('/project/:project/add', aclProject, (req, res) => {
    acl.addUserRoles(req.body.username, req.params.project);
    res.sendStatus(200);
});

app.post('/project/:project/remove', aclProject, (req, res) => {
    acl.removeUserRoles(req.body.username, req.params.project);
    res.sendStatus(200);
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

/*
var zip = new AdmZip("./my_file.zip");
zip.extractAllTo(/target path/"/home/me/zipcontent/", /overwrite/true);
zip.addFile("test.txt", new Buffer("inner content of the file"), "entry comment goes here");
    // add local file
    zip.addLocalFile("/home/me/some_picture.png");
var willSendthis = zip.toBuffer();
*/


/* EDIT */

function amcCommande(res, cwd, params, callback){
     var amcPrepare = childProcess.spawn('auto-multiple-choice', params, {
        cwd: cwd
    });

    var log = '';
    var errorlog = '';
    amcPrepare.stdout.on('data', (data) => {
        log += data;
    });
    amcPrepare.stderr.on('data', (data) => {
        errorlog += data;
    });
    amcPrepare.on('close', (code) => {
        if (code !== 0){
            res.json({
                log: log,
                command: params,
                errorlog: errorlog,
                error: code});
        } else {
            callback(log);
        }
    });
}


app.post('/project/:project/preview', aclProject, (req, res) => {
    var OUT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/out';
    fs.readdirSync(OUT_FOLDER).forEach((item) => {
        fs.unlinkSync(OUT_FOLDER + '/' + item);
    });
    amcCommande(res, PROJECTS_FOLDER + '/' + req.params.project, [
        'prepare', '--with', 'pdflatex', '--filter', 'latex',
        '--out-corrige', 'out/out.pdf', '--mode', 'k',
        '--n-copies', '1', 'source.tex', '--latex-stdout'
    ], (log) => {
        var convert = childProcess.spawn('convert', [
            '-density', '120', 'out.pdf', 'out-%03d.png'
        ], {
            cwd: OUT_FOLDER
        });
        convert.on('close', () => {
            var pages = fs.readdirSync(OUT_FOLDER).filter((item) => {
                return item.indexOf('.png') > 0;
            });
            res.json({log: log, pages: pages});
        });
    });
});

app.get('/project/:project/out/:image', aclProject, (req, res) => {
    res.sendFile(PROJECTS_FOLDER + '/' + req.params.project + '/out/' + req.params.image);
});

/* PRINT */



app.post('/project/:project/print', aclProject, (req, res) => {
    var PROJECT_FOLDER = PROJECTS_FOLDER + '/' + req.params.project + '/';

    fs.readdirSync(PROJECT_FOLDER + 'pdf/').forEach((item) => {
        fs.unlinkSync(PROJECT_FOLDER + 'pdf/' + item);
    });

    //sujet.pdf, catalog.pdf, calage.xy
    amcCommande(res, PROJECT_FOLDER, [
        'prepare', '--with', 'pdflatex', '--filter', 'latex',
        '--mode', 's[c]', '--n-copies', '2', 'source.tex',
        '--prefix', PROJECT_FOLDER, '--latex-stdout'
    ], (logCatalog) => {
        //corrige.pdf for all series
        amcCommande(res, PROJECT_FOLDER, [
            'prepare', '--with', 'pdflatex', '--filter', 'latex',
            '--mode', 'k', '--n-copies', '2', 'source.tex',
            '--prefix', PROJECT_FOLDER, '--latex-stdout'
        ], (logCorrige) => {
            //create capture and scoring db
            amcCommande(res, PROJECT_FOLDER, [
                'prepare', '--mode', 'b', 'source.tex', '--prefix', PROJECT_FOLDER,
                '--data', PROJECT_FOLDER + 'data', '--latex-stdout'
            ], (logScoring) => {
                //create layout
                amcCommande(res, PROJECT_FOLDER, [
                    'meptex', '--src', PROJECT_FOLDER + 'calage.xy', '--data', PROJECT_FOLDER + 'data',
                     '--progression-id', 'MEP', '--progression 1'
                ], (logLayout) => {
                    //print
                    // optional split answer --split
                    amcCommande(res, PROJECT_FOLDER, [
                        'imprime', '--methode', 'file', '--output', PROJECT_FOLDER + 'pdf/sheet-%e.pdf',
                        '--sujet',  'sujet.pdf',  '--data',  PROJECT_FOLDER + 'data',
                         '--progression-id', 'impression', '--progression 1'
                    ], (logPrint) => {
                         var pdfs = fs.readdirSync(PROJECT_FOLDER + 'pdf/').filter((item) => {
                            return item.indexOf('.pdf') > 0;
                        });
                        res.json({
                            logCatalog: logCatalog,
                            logCorrige: logCorrige,
                            logScoring: logScoring,
                            logLayout: logLayout,
                            logPrint: logPrint,
                            pdfs: pdfs
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
    zip.file(APP_FOLDER, 'assets/print.bat', {name: 'print.bat'});
    zip.finalize();
});


/* TODO normalise between static, out, debug */
app.get('/project/:project/debug/:file', aclProject, (req, res) => {
    res.sendFile(PROJECTS_FOLDER + '/' + req.params.project + '/' + req.params.file);
});

/*

*/

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
    fs.copySync(req.files.file.path, path.resolve(PROJECTS_FOLDER, req.params.project, 'scans/', req.files.file.name));
    // don't forget to delete all req.files when done
    fs.unlinkSync(req.files.file.path);
    tmp.file((err, path, fd, cleanup) => {
        fs.writeFileSync(path, 'scans/' + req.files.file.name);
        //need to call getimage with file to get path of extracted files...
        amcCommande(res, PROJECT_FOLDER, [
            'getimages', '--progression-id', 'analyse', '--vector-density', '250', '--orientation', 'portrait', '--list', path
        ], (logImages) => {
            var params = [
                'analyse', '--tol-marque', '0.2,0.2', '--prop', '0.8', '--bw-threshold', '0.6', '--progression-id', 'analyse', '--progression', '1',
                '--n-procs', '0', '--projet', PROJECT_FOLDER, '--liste-fichiers',  path
            ];
            //--multiple //if copies
            amcCommande(res, PROJECT_FOLDER, params, (logAnalyse) => {
                res.json({
                    logImages: logImages,
                    logAnalyse: logAnalyse
                });
            });
        });
    });
});

//needed?
//auto-multiple-choice note --data /home/amc/projects/test/data --seuil 0.6 --grain "" --arrondi normal --notemax 22 --plafond --notemin "" --progression-id notation --progression 1

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
    database(req, res, (db) => {
        //TODO get $threshold
        var threshold = 0.5;
        var query = "SELECT p.student || '/' || p.page || ':' || p.copy as id, p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, "
        + '(SELECT ROUND(10* COALESCE(($threshold - MIN(ABS(1.0*black/total - $threshold)))/ $threshold, 0), 1) '
        + 'FROM capture_zone WHERE student=p.student AND page=p.page AND copy=p.copy AND type=4) s '
        + 'FROM capture_page p ORDER BY p.student, p.page, p.copy';

        db('all', query, {$threshold: threshold}, (rows) => {
            res.json(rows || []);
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

app.get('/project/:project/static/:image', aclProject, (req, res) => {
    res.sendFile(PROJECTS_FOLDER + '/' + req.params.project + '/cr/' + req.params.image);
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

//auto-multiple-choice association-auto --data /home/amc/projects/test/data --notes-id etu --liste /home/amc/projects/test/students.csv --liste-key matricule
//auto-multiple-choice association-auto --data /home/amc/projects/test/data --set --student student-sheet-number --copy copy-number --id student-id

app.get('/project/:project/students', aclProject, (req, res) => {
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

/*

linkt to page for question
layout_box + layout_question

*/

/* REPORT */

//auto-multiple-choice export --module ods --data /home/amc/projects/test/data --useall 1 --sort l --fich-noms /home/amc/projects/test/students.csv --output /home/amc/projects/test/exports/export.ods --option-out nom="hello world" --option-out groupsums=1 --option-out stats=1 --option-out columns=student.copy,student.key,student.name --option-out statsindic=1

/*
ANNOTATE

before CLEAN jpg and pdf!

>> auto-multiple-choice annote --xmlargs /tmp/AMC-PACK-xG4VfWxw.xml
[  15956,   0.11] Unpacked args: --debug /tmp/AMC-DEBUG-rB9THe_H.log --progression-id annote --progression 1 --projet /home/boris/MC-Projects/test/ --projets /home/boris/MC-Projects/ --ch-sign 2 --cr /home/boris/MC-Projects/test/cr --data /home/boris/MC-Projects/test/data --id-file  --taille-max 1000x1500 --qualite 100 --line-width 2 --indicatives  --symbols 0-0:none/#000000000000,0-1:mark/#ffff00000000,1-0:circle/#ffff00000000,1-1:circle/#0000ffff26ec --position marge --pointsize-nl 60 --verdict "%(name) (%(matricule)) Note: %(note final)"
TP: %(tp), score: %S/%M --verdict-question "%s/%m" --fich-noms /home/boris/MC-Projects/AMC/no_matricules.csv --noms-encodage UTF-8 --csv-build-name (nom|surname) (prenom|name) --no-rtl --changes-only

//http://home.gna.org/auto-qcm/auto-multiple-choice.en/AMC-annote.shtml
auto-multiple-choice annote --progression-id annote --progression 1 --projet /home/amc/projects/test --projets /home/amc/projects/ --ch-sign 2 --cr /home/amc/projects/test/cr --data /home/amc/projects/test/data --taille-max 1000x1500 --qualite 100 --line-width 2 --symbols 0-0:none/#000000000000,0-1:mark/#ffff00000000,1-0:circle/#ffff00000000,1-1:circle/#0000ffff26ec --position marge --pointsize-nl 60  --verdict "%(name) (%(matricule)) Note: %(note final)\bTP: %(tp), score: %S/%M" --verdict-question "%s/%m" --fich-noms /home/amc/projects/test/notes.csv --changes-only

>> auto-multiple-choice regroupe --xmlargs /tmp/AMC-PACK-4LVxmEEG.xml
[  15959,   0.09] Unpacked args: --debug /tmp/AMC-DEBUG-rB9THe_H.log --id-file  --no-compose --projet /home/boris/MC-Projects/test/ --sujet /home/boris/MC-Projects/test/DOC-sujet.pdf --data /home/boris/MC-Projects/test/data --tex-src /home/boris/MC-Projects/test/source.tex --with pdflatex --filter latex --filtered-source /home/boris/MC-Projects/test/DOC-filtered.tex --n-copies 4 --progression-id regroupe --progression 1 --modele (name) --fich-noms /home/boris/MC-Projects/AMC/no_matricules.csv --noms-encodage UTF-8 --csv-build-name (nom|surname) (prenom|name) --single-output  --sort l --register --no-force-ascii
[  15959,   0.09] dir = /tmp/AcxYeia14o

(N)
is replaced by the student's name.
(ID)
is replaced by the student number.
(COL)

auto-multiple-choice regroupe --no-compose --projet /home/amc/projects/test/ --sujet /home/amc/projects/test/sujet.pdf --data /home/amc/projects/test/data --progression-id regroupe --progression 1 --modele "(name)" --fich-noms /home/amc/projects/test/notes.csv --register --no-force-ascii
*/

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
