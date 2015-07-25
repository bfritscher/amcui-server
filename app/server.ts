///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
import fs = require('fs');
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
var multipartMiddleware = multiparty();
//import AdmZip = require('adm-zip');
/*
var zip = new AdmZip("./my_file.zip");
zip.extractAllTo(/target path/"/home/me/zipcontent/", /overwrite/true);
zip.addFile("test.txt", new Buffer("inner content of the file"), "entry comment goes here");
    // add local file
    zip.addLocalFile("/home/me/some_picture.png");
var willSendthis = zip.toBuffer();
*/

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

/* TEST AREA */
app.get('/', (req, res) => {
    res.send('Hello World3!');
});

app.post('/upload', multipartMiddleware, function (req: multiparty.Request, resp) {
  console.log(req.body, req.files);
  // don't forget to delete all req.files when done
});

app.get('/project/:project/config', (req, res) => {
    var filename = path.resolve(__dirname, '../app/projects/' + req.params.project + '/options.xml');
    fs.readFile(filename, 'utf-8', function(err, data) {
        xml2js.parseString(data, {explicitArray: false}, function (err, result) {
            var builder = new xml2js.Builder();
            result.projetAMC.seuil = 1.0;
            var xml = builder.buildObject(result);
            fs.writeFile(filename, xml);
            res.json(result.projetAMC.seuil);
        });
    });
});


app.get('/project/create/:project', (req, res) => {
    // create project
    var root = path.resolve(__dirname, '../app/projects/', req.params.project);
    if (!fs.existsSync(root)) {
        mkdirp.sync(root + '/cr/corrections/jpg');
        mkdirp.sync(root + '/cr/corrections/pdf');
        mkdirp.sync(root + '/cr/zooms');
        mkdirp.sync(root + '/cr/diagnostic');
        mkdirp.sync(root + '/data');
        mkdirp.sync(root + '/scans');
        mkdirp.sync(root + '/exports');
        mkdirp.sync(root + '/src');
        //option file
        //role, resource, permission
        acl.allow(req.params.project, '/project/' + req.params.project, 'admin');
        //user, role
        acl.addUserRoles(req.user.username, req.params.project);
        res.sendStatus(200);
    }else{
        res.sendStatus(403);
    }
});

app.post('/allow', (req, res) => {
    acl.allow(req.body.project, '/project/' + req.body.project, 'admin');
    acl.addUserRoles(req.body.username, req.body.project);
    res.sendStatus(200);
});

app.get('/project/test', (req, res) => {
    acl.allowedPermissions(req.user.username, 'test5', (err, roles) => {
        res.send('Hello secure! #' + req.user.username + JSON.stringify(roles)  + JSON.stringify(err));
    });

});

app.get('/project/:project/info', aclProject, (req, res) => {
        res.send('Your project! #' + req.user.username);
});

/* API */
app.post('/login', (req, res, next) => {
    if (req.body.password && req.body.username) {
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
        redisClient.get('user:' + req.body.username, function(err, reply) {
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
                var newUser = {username: req.body.username, password: password};
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

/*

Project Auth

Create a Project

Change options of a project
	-> some trigger other functions? (marks, annotations)

List Project

Upload a project?

Edit Latex
	-> recompute markings?

Preview Latex

Print
   ->before check layout (user interaction?)

Upload scans

Get capture data state

Manage manually pages
	-> zones

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

function database(req, res, callback){
    var project = req.params.project;
    var db = new sqlite3.Database('app/projects/' + project + '/data/capture.sqlite', (err) => {
        if (err){
            res.status(500).send(err);
        }
        db.serialize(() => {
            db.exec("ATTACH DATABASE 'app/projects/" + project + "/data/layout.sqlite' AS layout");
            db.exec("ATTACH DATABASE 'app/projects/" + project + "/data/association.sqlite' AS assoc");
            var dbHandled = (method, query, params, success) => {
                var internalCallback = (err, rows) => {
                    if (err){
                        res.status(500).send(err);
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
}

/*
version > 1.2.1 feature seuil-up not supported

 */


/* PROJECT Management */


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

/* CAPTURE*/

/*
debug "Removing data capture for ".pageids_string(@id);
	#
	# 1) get image files generated, and remove them
	#
	my $crdir=$shortcuts->absolu($projet{'options'}->{'cr'});
	my @files=();
	#
	# scan file
	push @files,$shortcuts->absolu($projet{'_capture'}->get_scan_page(@id));
	#
	# layout image, in cr directory
	push @files,$crdir.'/'
	  .$projet{'_capture'}->get_layout_image(@id);
	#
	# annotated scan
	push @files,$crdir.'/corrections/jpg/'
	  .$projet{'_capture'}->get_annotated_page(@id);
	#
	# zooms
	push @files,map { $crdir.'/zooms/'.$_ } grep { defined($_) }
	  ($projet{'_capture'}->get_zones_images(@id,ZONE_BOX));
	#
	for (@files) {
	  if (-f $_) {
	    debug "Removing $_";
	    unlink($_);
	  }
	}
	#
	# 2) remove data from database
	#
	$projet{'_capture'}->delete_page_data(@id);

	if($projet{'options'}->{'auto_capture_mode'} == 1) {
	  $projet{'_scoring'}->delete_scoring_data(@id[0,2]);
	  $projet{'_association'}->delete_association_data(@id[0,2]);
	}


*/

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
        var threshold = 0.5;
        var query = "SELECT p.student || '/' || p.page || ':' || p.copy as id, p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, "
        + '(SELECT ROUND(10* COALESCE(($threshold - MIN(ABS(1.0*black/total - $threshold)))/ $threshold, 0), 1) '
        + 'FROM capture_zone WHERE student=p.student AND page=p.page AND copy=p.copy AND type=4) s '
        + 'FROM capture_page p ORDER BY p.student, p.page, p.copy';

        db('all', query, {$threshold: threshold}, (rows) => {
            res.json(rows);
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

app.get('/project/:project/static/:image', aclProject, (req, res) => {
    res.sendFile(path.resolve(__dirname, '../app/projects/' + req.params.project + '/cr/' + req.params.image));
});

/*
page for question
layout_box + layout_question

*/

/* ZONES */

/*
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
//TODO handle errors

if(params.student && params.page && params.copy) {
    out << new JsonBuilder(sql.rows(''';''',
        [params.student, params.page, params.copy]))
}else{
  println 'error required parameters: student, page and copy'
}
*/
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

/* REPORT */
/*
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
//sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/scoring.sqlite' AS scoring")
//sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/association.sqlite' AS assoc")

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

/*
original query from AMC
     $dt=$self->{'_scoring'}->variable('darkness_threshold');
         'tickedSums'=>{'sql'=>
		    "SELECT * FROM (SELECT zone.id_a AS question,zone.id_b AS answer,SUM(CASE"
		    ." WHEN why=\"V\" THEN 0"
		    ." WHEN why=\"E\" THEN 0"
		    ." WHEN zone.manual >= 0 THEN zone.manual"
		    ." WHEN zone.total<=0 THEN -1"
		    ." WHEN zone.black >= ? * zone.total THEN 1"
		    ." ELSE 0"
		    ." END) AS nb"
		    ." FROM $t_zone AS zone, scoring.scoring_score AS score"
		    ." ON zone.student=score.student AND zone.copy=score.copy AND zone.id_a=score.question"
		    ." WHERE zone.type=? GROUP BY zone.id_a,zone.id_b)"
		    ." UNION"
		    ." SELECT * FROM (SELECT question,\"invalid\" AS answer,"
		    ." COUNT(*)-COUNT(NULLIF(why,\"E\")) AS nb"
		    ." FROM scoring.scoring_score"
		    ." GROUP BY question)"
		    ." UNION"
		    ." SELECT * FROM (SELECT question,\"empty\" AS answer,"
		    ." COUNT(*)-COUNT(NULLIF(why,\"V\")) AS nb"
		    ." FROM scoring.scoring_score"
		    ." GROUP BY question)"
		    ." UNION"
		    ." SELECT * FROM (SELECT question,\"all\" AS answer,COUNT(*) AS nb"
		    ." FROM scoring.scoring_score"
		    ." GROUP BY question)"
*/

/*
def query = '''
SELECT question, 'all' AS answer, COUNT(*) AS nb,
0 as correct
FROM scoring.scoring_score
GROUP BY question
UNION
SELECT question, 'invalid' AS answer, COUNT(*)-COUNT(NULLIF(why,'E')) AS nb,
3 as correct
FROM scoring.scoring_score
GROUP BY question
UNION
SELECT question, 'empty' AS answer, COUNT(*)-COUNT(NULLIF(why,'V')) AS nb,
2 as correct
FROM scoring.scoring_score
GROUP BY question
UNION
SELECT s.question AS question, z.id_b AS answer,
SUM(CASE
WHEN s.why='V' THEN 0
WHEN s.why='E' THEN 0
WHEN z.manual >= 0 THEN z.manual
WHEN z.total<=0 THEN 0
WHEN z.black >= ?1 * z.total THEN 1
ELSE 0
END) AS nb, a.correct AS correct
FROM capture_zone z JOIN scoring.scoring_score s
ON z.student = s.student AND
z.copy = s.copy AND
s.question = z.id_a
AND z.type = 4
JOIN scoring.scoring_answer a ON a.student = s.student
AND a.question = s.question
AND z.id_b = a.answer
GROUP BY z.id_a, z.id_b, a.correct
'''

def query2 = '''SELECT t.question, t.title, q.indicative, q.type, s.max, AVG(s.score) / s.max AS avg
FROM scoring.scoring_title t JOIN scoring.scoring_question q ON  t.question = q.question
LEFT JOIN scoring.scoring_score s ON s.question = t.question
WHERE q.strategy <> 'auto=0'
GROUP BY t.question, t.title, q.indicative, q.type, s.max
ORDER BY t.question
'''

def questions = [:]


sql.eachRow(query2){ row ->
    def a = new Expando()
    a.question = row.question
    a.title = row.title
    a.indicative = row.indicative
    a.type = row.type
    a.max = row.max
    a.avg = row.avg
    a.answers = []
    questions[row.question] = a
}

sql.eachRow(query, [sql.firstRow("SELECT value FROM scoring.scoring_variables WHERE name='darkness_threshold'").value]){ row ->
    if(questions[row.question]){
        if(row.answer == 'all'){
            questions[row.question].total = row.nb
        }else{
            def a = new Expando()
            a.answer = row.answer
            a.nb = row.nb
            a.correct = row.correct
            questions[row.question].answers << a
        }
    }
}
*/

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
