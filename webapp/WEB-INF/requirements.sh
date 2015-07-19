#!/bin/bash
curl -L -O http://search.maven.org/remotecontent?filepath=org/apache/ivy/ivy/2.4.0/ivy-2.4.0.jar
java -jar ivy-2.4.0.jar -ivy ivy.xml -retrieve "lib/[artifact]-[revision](-[classifier]).[ext]"