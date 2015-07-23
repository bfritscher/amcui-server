///<reference path="../typings/tsd.d.ts" />

require('dotenv').load();
require('source-map-support').install();
import cors = require('cors');
import express = require('express');
import bodyParser = require('body-parser');
import errorHandler = require('errorhandler');
import sqlite3 = require('sqlite3');

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


app.get('/students', (req, res) => {
    // LIST OF STUDENTS with their name field and if matched
    var db = new sqlite3.Database('app/projects/test/data/capture.sqlite', (err) => {
        if (err){
            res.status(500).send(err);
        }
        db.serialize(() => {
            db.exec("ATTACH DATABASE 'app/projects/test/data/layout.sqlite' AS layout");
            db.exec("ATTACH DATABASE 'app/projects/test/data/association.sqlite' AS assoc");

            var query = 'SELECT p.student, p.page, p.copy, z.image, a.manual, a.auto '
            + 'FROM capture_page p JOIN layout.layout_namefield l ON p.student=l.student AND p.page = l.page '
            + 'LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy '
            + 'LEFT JOIN assoc.association_association a ON a.student = p.student AND a.copy = p.copy';

            db.all(query, (err, rows) => {
                res.json(rows);
            });
        });
    });
});

/* CAPTURE*/

/*
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/association.sqlite' AS assoc")

def query = '''SELECT p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, 8 s FROM
capture_page p
*/
/*LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy
GROUP BY p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual */
/*
'''
if(params.student && params.page && params.copy) {
  query =  "SELECT p.* FROM capture_page p WHERE p.student=?1 AND p.page=?2 AND p.copy=?3"
  out << new JsonBuilder(sql.rows(query, [params.student, params.page, params.copy]))

}else{
   out << new JsonBuilder(sql.rows(query))
}
*/
/*

{'sql'=>"SELECT student,page,copy,mse,timestamp_auto,timestamp_manual"
      .",CASE WHEN timestamp_auto>0 AND mse>? THEN ?"
      ."      ELSE ?"
      ."  END AS mse_color"
      .",CASE WHEN timestamp_manual>0 THEN ?"
      ."      WHEN timestamp_auto>0 THEN ?"
      ."      ELSE ?"
      ."  END AS color"
      .",CASE WHEN timestamp_manual>0 THEN timestamp_manual"
      ."      ELSE timestamp_auto"
      ."  END AS timestamp"
      .",(SELECT MIN(ABS(1.0*black/total-?))"
      ."   FROM $t_zone"
      ."   WHERE $t_zone.student=$t_page.student"
      ."     AND $t_zone.page=$t_page.page AND $t_zone.copy=$t_page.copy"
      ."     AND $t_zone.type=? AND total>0) AS delta"
      .",(SELECT MIN(ABS(1.0*black/total-?))"
      ."   FROM $t_zone"
      ."   WHERE $t_zone.student=$t_page.student"
      ."     AND $t_zone.page=$t_page.page AND $t_zone.copy=$t_page.copy"
      ."     AND $t_zone.type=? AND total>0) AS delta_up"
      ." FROM $t_page"},

*/

/* ZONES */

/*
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
//TODO handle errors

if(params.student && params.page && params.copy) {
    out << new JsonBuilder(sql.rows('''SELECT z.id_a AS question, z.id_b AS answer, z.total, z.black,
        z.manual, max(CASE WHEN p.corner = 1 THEN p.x END) as x0,
        max(CASE WHEN p.corner = 1 THEN p.y END) as y0,
        max(CASE WHEN p.corner = 2 THEN p.x END) as x1,
        max(CASE WHEN p.corner = 2 THEN p.y END) as y1,
        max(CASE WHEN p.corner = 3 THEN p.x END) as x2,
        max(CASE WHEN p.corner = 3 THEN p.y END) as y2,
        max(CASE WHEN p.corner = 4 THEN p.x END) as x3,
        max(CASE WHEN p.corner = 4 THEN p.y END) as y3
        FROM capture_zone AS z
        JOIN capture_position as p ON z.zoneid=p.zoneid
        WHERE z.student=?1 AND z.page=?2 AND z.copy=?3 AND z.type=4 AND p.type=1
        GROUP BY z.zoneid, z.id_a, z.id_b, z.total, z.black, z.manual
        ORDER BY min(p.y), min(p.y);''',
        [params.student, params.page, params.copy]))
}else{
  println 'error required parameters: student, page and copy'
}
*/


/* REPORT */

def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
//sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/scoring.sqlite' AS scoring")
//sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/association.sqlite' AS assoc")


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
