///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
import cors = require('cors');
import express = require('express');
import bodyParser = require('body-parser');
import errorHandler = require('errorhandler');
import sqlite3 = require('sqlite3');
import path = require('path');

var app = express();
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit: '50mb'}));

var env = process.env.NODE_ENV || 'development';
if (env === 'development') {
    app.use(errorHandler({ dumpExceptions: true, showStack: true }));
    sqlite3.verbose();
    //app.use(express.static(__dirname + '/../../avionmake/app'));
    //app.use('/scripts', express.static(__dirname + '/../../avionmake/.tmp/scripts'));
    //app.use('/styles', express.static(__dirname + '/../../avionmake/.tmp/styles'));
    //app.use('/bower_components', express.static(__dirname + '/../../avionmake/bower_components'));
}
else if (env === 'production') {
    app.use(express.static(__dirname + '/public'));
}

var project = 'test'; //sqla-2015-exa';

app.get('/', (req, res) => {
    res.send('Hello World3!');
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

function database(res, callback){
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

app.get('/students', (req, res) => {
    // LIST OF STUDENTS with their name field and if matched
    database(res, (db) => {
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

app.get('/missing', (req, res) => {
    database(res, (db) => {
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


app.get('/capture', (req, res) => {
    database(res, (db) => {
        var threshold = 0.15;
        + '(SELECT ROUND(10* COALESCE(($threshold - MIN(ABS(1.0*black/total - $threshold)))/ $threshold, 0), 1) '
        + 'FROM capture_zone WHERE student=p.student AND page=p.page AND copy=p.copy AND type=4) s '
        + 'FROM capture_page p ORDER BY p.student, p.page, p.copy';

        db('all', query, {$threshold: threshold}, (rows) => {
            res.json(rows);
        });
    });
});

app.get('/capture/:student/:page\::copy', (req, res) => {
    database(res, (db) => {
        var query = 'SELECT * FROM capture_page WHERE student=$student AND page=$page AND copy=$copy';
        db('get', query, {$student: req.params.student, $page: req.params.page, $copy: req.params.copy}, (row) => {
            res.json(row);
        });
    });
});

app.get('/static/:image', (req, res) => {
    res.sendFile(path.resolve(__dirname, '../app/projects/' + project + '/cr/' + req.params.image));
});


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
app.get('/zones/:student/:page\::copy', (req, res) => {
    database(res, (db) => {
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


var server = app.listen(process.env.SERVER_PORT, '0.0.0.0');
server.on('listening', function(){
    console.log('server listening on port %d in %s mode', server.address().port, app.settings.env);
});

export var App = app;
