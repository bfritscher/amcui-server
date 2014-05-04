import groovy.sql.Sql 
import groovy.json.*
import com.xlson.groovycsv.CsvParser
 
def sql = Sql.newInstance("jdbc:sqlite:/home/boris/MC-Projects/AMC/data/capture.sqlite", "org.sqlite.JDBC")
sql.execute("ATTACH DATABASE '/home/boris/MC-Projects/AMC/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE '/home/boris/MC-Projects/AMC/data/association.sqlite' AS assoc")


//SELECT value FROM association_variables WHERE name='key_in_list'

// csv must have one unique column, + fields name and surname

if(params.csv){
    def data = new CsvParser().parse(new File('/home/boris/MC-Projects/AMC/notes.csv').newReader())
    println data[0].columns
    data.each{
        println it.values
    }
}else{
/*
original query from AMC
// in all pages which have a namefield get namefields zone image url
SELECT a.student AS student,a.page AS page,a.copy AS copy, b.image AS image
FROM ( SELECT c.student,c.page,c.copy
    FROM (SELECT * FROM capture_page WHERE timestamp_auto>0 OR timestamp_manual>0 ) AS c,
    layout.layout_namefield AS l ON c.student=l.student AND c.page=l.page ) AS a
    LEFT OUTER JOIN ( SELECT student,page,copy,image FROM capture_zone WHERE type=2 ) AS b
    ON a.student=b.student AND a.page=b.page AND a.copy=b.copy'''
*/

def query = '''SELECT p.student, p.page, p.copy, z.image, a.manual, a.auto 
FROM capture_page p JOIN layout.layout_namefield l ON p.student=l.student AND p.page = l.page 
LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy 
LEFT JOIN assoc.association_association a ON a.student = p.student AND a.copy = p.copy'''

out << new JsonBuilder(sql.rows(query))
}