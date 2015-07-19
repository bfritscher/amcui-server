import groovy.sql.Sql 
import groovy.json.*
import com.xlson.groovycsv.CsvParser
 
def sql = Sql.newInstance("jdbc:sqlite:/home/boris/MC-Projects/AMC/data/capture.sqlite", "org.sqlite.JDBC")
//sql.execute("ATTACH DATABASE '/home/boris/MC-Projects/AMC/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE '/home/boris/MC-Projects/AMC/data/scoring.sqlite' AS scoring")
//sql.execute("ATTACH DATABASE '/home/boris/MC-Projects/AMC/data/association.sqlite' AS assoc")


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

out << new JsonBuilder(questions.values())
