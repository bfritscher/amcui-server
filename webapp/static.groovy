response.contentType = 'image/png'
//TODO: security limit to Projectdir!!
sout << new FileInputStream(new File('/home/boris/MC-Projects/AMC' + params.id))
