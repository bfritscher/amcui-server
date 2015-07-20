var sqlite3 = require('sqlite3').verbose();
/*
def sql = Sql.newInstance("jdbc:sqlite:webapps/amcui/project/data/capture.sqlite", "org.sqlite.JDBC")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/layout.sqlite' AS layout")
sql.execute("ATTACH DATABASE 'webapps/amcui/project/data/association.sqlite' AS assoc")
*/

var db = new sqlite3.Database('data/capture.sqlite');
db.serialize(function(){
	db.exec("ATTACH DATABASE 'data/layout.sqlite' AS layout");
	db.exec("ATTACH DATABASE 'data/association.sqlite' AS assoc");

	var query = "SELECT p.student, p.page, p.copy, z.image, a.manual, a.auto "
	+ "FROM capture_page p JOIN layout.layout_namefield l ON p.student=l.student AND p.page = l.page "
	+ "LEFT JOIN capture_zone z ON z.type = 2 AND z.student = p.student AND z.page = p.page AND z.copy = p.copy "
	+ "LEFT JOIN assoc.association_association a ON a.student = p.student AND a.copy = p.copy";

	db.each(query, function(err, row) {
	      console.log(err, row);
	  });
});
