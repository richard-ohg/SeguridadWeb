#!/usr/bin/python

import cgi, cgitb, os

software = os.environ.get("SERVER_SOFTWARE", '')

if os.environ.get("REQUEST_METHOD") == 'POST':
    form = cgi.FieldStorage()
    nombre = cgi.escape(form.getvalue('nombre'))
    html = """
    <html>
    <head>
    <title>Metodo POST</title>
    </head>
    <body style="color:yellow;background-color:blue;margin-top:50px;">
    <center>
    <h1>Hola %s</h1>
    <img src="https://melbournechapter.net/images/kitten-transparent-white-5.png" width="800px;"/>
    </center>
    <p style="color:white;">Servidor %s</p>
    </body>
    </html>    
"""
    print html % (nombre, software)
elif os.environ.get("REQUEST_METHOD") == 'GET':
    print "Content-Type: text/html\n"
    html = """<html>
    <head>
    <title>Metodo GET</title>
    </head>
    <body style="color:yellow;background-color:blue;margin-top:50px;">
    <form method="POST" action="">
    Ingresa tu nombre: <input name="nombre" type="text" />
    <input type="submit" value="Enviar"/>
    </form>
    <p style="color:white;">Servidor %s</p>
    </body>
    </html>
"""
    print html % (software)

