import groovy.sql.Sql 
import groovy.json.*
 
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/association.sqlite' AS assoc")

def query = '''SELECT p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual, 8 s FROM 
capture_page p 
/*LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy
GROUP BY p.student, p.page, p.copy, p.mse, p.timestamp_auto, p.timestamp_manual */

'''
if(params.student && params.page && params.copy) {
  query =  "SELECT p.* FROM capture_page p WHERE p.student=?1 AND p.page=?2 AND p.copy=?3"
  out << new JsonBuilder(sql.rows(query, [params.student, params.page, params.copy]))
 
}else{
   out << new JsonBuilder(sql.rows(query))
}
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


