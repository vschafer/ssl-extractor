SSL Extractor
============

A simple Java application which connects to an SSL/TLS port and extracts 
all certificates presented by the server. Certificates are stored in PEM 
format and can be directly imported to e.g. Java keystores.

Build the jar using maven with:

maven package
or use the existing jar from release folder.

Usage:

java -jar release/sslextractor-0.9.jar host port
e.g.
java -jar release/sslextractor-0.9.jar github.com 443