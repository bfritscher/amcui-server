import groovy.sql.Sql 
import groovy.json.*

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