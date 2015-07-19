response.contentType = 'image/png'
//TODO: security limit to Projectdir!!
sout << new FileInputStream(new File('webapps/amcui/project' + params.id))
