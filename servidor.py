#!/usr/bin/python3

import optparse
import socket
import os
import subprocess
import re
import datetime
import waf


# Diccionario que nos servirá para el Content-type de las cabeceras
list_content_type = {'txt':'text/plain',
'hmtl':'text/html',
'jpeg':'image/jpeg',
'png':'image/png',
'js':'text/javascript',
'zip':'application/zip',
'xml':'application/xml',
'mp4':'video/mp4',
'pdf':'application/pdf'}

# Respuesta a un código 200
html_response_200 = """
<h1> Bienvenido ;) </h1>
"""

# Respuesta a un código 403
html_response_403 = """
<h1> Error 403: Error en permisos del archivo </h1>
"""

# Respuesta a un código 404
html_response_404 = """
<h1> Error 404: Recurso no encontrado </h1>
"""

# Respuesta a un código 405
html_response_405 = """
<h1> Error 405: Método no permitido </h1>
"""

# Respuesta a un código 500
html_response_500 = """
<h1> Error 500: Error al ejecutar un script </h1>
"""


def options():
    '''
	    Función que permite agregar las banderas correspondientes para el uso del
	    programa ejecutado como script.

        :return: retorna las opciones elegidas al momento de ejecutar el programa
    '''
    parser = optparse.OptionParser()
    parser.add_option('-p','--port', dest='port', type=int, default=8080, help='Puerto del servidor.')
    parser.add_option('-d','--directory', dest='directory', default='.', help='Directorio a mostrar')
    parser.add_option('-b','--bitacora', dest='bitacora', default='.', help='Directorio para bitacora')
    parser.add_option('-w','--waf', dest='waf', default=False, help='Archivo de reglas para wl WAF')
    opts,args = parser.parse_args()
    return opts

def changeDirectory(directory):
    '''
        Función para cambiarnos de directorio

        :param directory: ruta relativa al directorio donde correremos el servidor
        :return: retorna falso si se ingresa una ruta de más de 3 niveles o no existe el nombre del directorio
        :return: retorna true si se pudo cambiar de directorio
    '''
    if directory.find("../../../") >= 0:
        print("No puedes acceder más allá de 2 niveles")
        return False
    else:
        try:
            os.chdir(directory)
            return True
        except: 
            return False

def createSocket(port, host='0.0.0.0'):
    '''
        Función para la creación de un socket

        :param port: puerto donde que se ocupará para abrir el socket
        :param host: host para permitir acceso al socket, por defecto está abierto a todos
        :return: retorna el socket
    '''
    mySocket = socket.socket()
    mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mySocket.bind((host,port))
    mySocket.listen(1)
    return mySocket

def createResponse(codigo, msg, type, text):
    '''
        Función para crear el mensaje de respuesta del servidor

        :param codigo: código de respuesta del servidor
        :param msg: mensaje de respuesta dependiendo del código
        :param type: string que irá en la cabecera Content-type
        :param text: cuerpo del mensaje
        :return: mensaje de respuesta del servidor compuesto de cabecera + cuerpo 
    '''
    http_response = "HTTP/1.1 {} {}\r\n".format(codigo,msg)
    http_response += "Content-Type: {}\r\n".format(type)
    http_response += "Connection: close\r\n\r\n"
    http_response += text      
    return http_response

def fileContent(file):
    '''
        Función para obetener el contenido de un archivo
        
        :param file: nombre del archivo
        :return: retorna el contenido del archivo como un string o False si el archivo no existe
    '''
    try:
        with open(file,'rb') as f:
            return str(f.read())
    except:
        # No existe el archivo
        return False

def getNameFile(string):
    '''
        Función para obtener el nombre de un archivo
        
        :param string: recurso de la petición
        :return: retorna el nombre del archivo pedido
    '''
    return string.split('/')[-1]

def getTypeFile(file):
    '''
        Función para obtener la extensión de un archivo

        :param file: nombre del archivo
        :return: retorna la extensión del archivo (.txt, .html, etc.)
    '''
    return file.split('.')[-1]

def getContentTypeFile(type_file):
    '''
        Función para obtener el Content-type de un archivo a partir de la extensión
       
        :param type_file: extensión del archivo
        :return: el valor del Content-type, si no existe, se pondrá el Content-type de un txt
    '''
    for key,value in list_content_type.items():
        if key == type_file:
            return value
    # No encontró el tipo de dato, se pondrá txt por defecto
    return list_content_type['txt']

def getCurrentDirectory():
    '''
        Función para obtener el directorio actual donde se corre el servidor
        
        :return: retorna el nombre del directorio
    '''
    return os.getcwd().split('/')[-1]

def setEnviromentVar(dc_root, port_remote, host_remote, port, user_agent, method, host, cookie="", query="", http_referer=""):
    '''
        Función para crear las variables de entorno para el cgi
        
        :param dc_root: The root directory of your server
        :param port_remote: The port the visitor is connected to on the web server
        :param host_remote: The hostname of the visitor (if your server has reverse-name-lookups on; otherwise this is the IP address again) 
        :param port: The port number your server is listening on
        :param user-agent: The browser type of the visitor
        :param method: REQUEST_METHOD
        :param host: Your server's fully qualified domain name (e.g. www.cgi101.com)
        :param cookie: The visitor's cookie, if one is set
        :param query: The query string 
        :param http_referer: The URL of the page that called your program
        :return: diccionario con las variables de entorno
    '''
    env = {}
    env['DOCUMENT_ROOT'] = dc_root
    env['HTTP_COOKIE'] = cookie
    env['HTTP_REFERER'] = http_referer
    env['HTTP_USER_AGENT'] = user_agent
    env['QUERY_STRING'] = query
    env['REMOTE_ADDR'] = host_remote
    env['REMOTE_PORT'] = port_remote
    env['REQUEST_METHOD'] = method
    env['SERVER_NAME'] = host
    env['SERVER_PORT'] = port
    env['SERVER_SOFTWARE'] = "No es apache/1.0"
    return env 

def getUserAgent(request):
    '''
        Función para obtener el User-Agent a partir una petición spliteada
        
        :param request: lista generada a partir de usar el método split en la petición 
        :return: retorna el user-agent o una cadena vacia en caso de no encontrarlo
    '''
    patron = 'User-Agent: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getCookie(request):
    '''
        Función para obtener las cookies de una petición

        :param request: lista generada a partir de usar el método split en la petición 
        :return: retorna las cookies o una cadena vacia en caso de no encontrarlo
    '''
    patron = 'Cookie: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getHeaderHost(request):
    '''
        Función para obtener el host de una petición

        :param request: lista generada a partir de usar el método split en la petición 
        :return: retorna el host o una cadena vacia en caso de no encontrarlo
    '''
    patron = 'Host: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getHttpReferer(request):
    '''
        Función para obtener el http_referer de una petición

        :param request: lista generada a partir de usar el método split en la petición 
        :return: retorna el http_referer o una cadena vacia en caso de no encontrarlo
    '''
    patron = 'Referer: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""



if __name__ == "__main__":
    '''
        Función principal

    '''
    # Obtenemos las opciones que ingresamos al ejecutar el programa
    opt = options()

    # En caso de haber puesto otro directorio
    if changeDirectory(opt.directory):
        print("Accediendo al directorio ", getCurrentDirectory())
    else:
         print("Se usó directorio actual: ", getCurrentDirectory())

    # Creamos el directorio para guardar los archivos de las bitácoras      
    os.system('mkdir -p '+opt.bitacora)

    # Creamos el socket con el puerto
    sock = createSocket(opt.port)

    # Ciclo infinito para mantener la comunicación del socket
    while True:

        # Obtenemos la dirección y la conexión del socket
        conn, addr = sock.accept()
        print ("Connection from: " + str(addr))
        
        # Obtenemos los datos enviados por el socket
        data = conn.recv(1024).decode()
        
        # Si no se ha enviado nada, terminamos el ciclo
        if not data:
            break
        
        # Lista generada a partir de un split a la petición
        arg = data.split() 
        
        # Lista 2 generada a partir de un split a la petición, nos sevrirá para obtener cada header de la petición
        arg2 = data.split('\r\n')
        
        # Obtenemos los headers como user-agent, cookie, method y query, host, http_referer 
        user_agent = getUserAgent(arg2)
        cookie =  getCookie(arg2)
        method, query = waf.getMethodAndQuery(arg2)
        hostEnv = getHeaderHost(arg2)
        http_referer = getHttpReferer(arg2)

        # Obtenemos el nombre del archivo y el tipo de datos a partir de la query de la petición
        name_file = getNameFile(query)
        type_file = getTypeFile(name_file)

        # Mandamos la información al archivo de bitácoras access.log
        os.system('echo "' + addr[0] + ' ' + datetime.datetime.now().strftime("%x:%X") + ' ' + arg2[0] + ' 200 - ' + user_agent + '" >> ' + opt.bitacora +'/access.log')
        
        # if-else para checar el método http
        # Método GET
        if method == 'GET':
            
            # Vemos si se pidió un recurso con extensión py, pl, php o cgi 
            if type_file == 'py' or type_file == 'php' or type_file == 'pl' or type_file == 'cgi':

                # Asignamos las variables de entorno para ejecutar el archivo
                env = setEnviromentVar(str(os.getcwd()), str(addr[1]), str(addr[0]), str(opt.port), user_agent, method, hostEnv, cookie, query, http_referer)
                
                # Try-except para capturar los errores y mandar mensajes de error
                try:
                    # Utilizamos la función Popen del módulo subprocess para abrir el archivo a ejecutar y asignarle las variables de entorno
                    with subprocess.Popen([name_file], stdout=subprocess.PIPE, env=env) as proc: 
                        # Armamos la respuesta y la mandamos por el socket, se mandará el resultado de ejecutar el archivo seleccionado                     
                        conn.sendall(createResponse(200, 'OK', 'text/html', proc.stdout.read().decode('utf-8')).encode('utf-8')) 
                
                except IOError:
                    # En caso de que no se pueda abrir el archivo mandamos error 403
                    os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:403] [client ' + arg2[0] + '] No tiene permisos: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
                    # Reportamos el error en el archivo errors.log
                    conn.sendall(createResponse(403,'FORBIDDEN','text/html',html_response_403).encode('utf-8'))
                
                except:
                    # En caso de que el archivo mande error al ejecutar mandamos error 500
                    conn.sendall(createResponse(500,'INTERNAL SERVER ERROR','text/html',html_response_500).encode('utf-8'))
                    # Reportamos el error en el archivo errors.log
                    os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:500] [client ' + arg2[0] + '] Error al ejecutar: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
            else:  
                # Para cuando entre al navegador sin acceder a ningun recurso
                if query == '/':
                    # Respondemos un código de 200
                    conn.sendall(createResponse(200, 'OK', 'text/html', html_response_200).encode('utf-8'))
                else:
                    # Guardamos el contenido del archivo que se solicitó
                    content_type_value = getContentTypeFile(type_file)
                    file_cont = fileContent(name_file)
                    # Si existe el archivo
                    if file_cont:
                        # Respondemos un código de 200
                        conn.sendall(createResponse(200, 'OK', content_type_value, file_cont).encode('utf-8'))
                    else:
                        # Respondemos un código 404 si el archivo solicitado no fue encontrado
                        conn.sendall(createResponse(404,'NOT FOUND', 'text/html', html_response_404).encode('utf-8'))
                        # Reportamos los errores en errors.log
                        os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:404] [client ' + arg2[0] + '] Recurso no encontrado: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')

        # Método HEAD
        elif method == 'HEAD':
            # Solo respondemos un código 200 
            conn.sendall(createResponse(200, 'OK', 'text/html', html_response_200).encode('utf-8'))
        
        # Método POST
        elif method == 'POST':
            # Lista que nos servirá para separar las cabeceras y el cuerpo
            arg3 = data.split('\r\n\r\n')
            
            # Filtramos el query de la petición
            query = arg3[-1]+'\n'

            # Asignamos las variables de entorno para el estandar cgi
            env = setEnviromentVar(str(os.getcwd()), str(addr[1]), str(addr[0]), str(opt.port), user_agent, method, hostEnv, cookie, http_referer = http_referer)
            
            #try - except para manejo de errores 
            try:
                # Ejecutamos el archivo .cgi poniendole un PIPE en su entrada estándar y un PIPE en su salida estándar asignandole las variables de entorno
                with subprocess.Popen(['post.cgi'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env) as proc: 
                    # Le pasamos a la entrada estándar la query
                    proc.stdin.write(query.encode('utf-8'))
                    # Cerramos el flujo a la entrada estándar
                    proc.stdin.close()
                    # Enviamos la respuesta con código 200 y la ejecución del archivo
                    conn.sendall(createResponse(200,'OK','text/html',proc.stdout.read().decode('utf-8')).encode('utf-8')) 
            except Exception as e:
                # En caso de error mandamos un error 403
                conn.sendall(createResponse(403,'FORBIDDEN','text/html',html_response_403).encode('utf-8'))
                # Reportamos en la bitácora los errores
                os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:403] [client ' + arg2[0] + '] Error con permisos: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
        # En caso de que no sea ninguno de los métodos anteriores
        else:
            # Mandamos error 405
            conn.sendall(createResponse(405,'METHOD NOT ALLOWED','txt',html_response_405).encode())
            # Reportamos el error en bit+acoras
            os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:405] [client ' + arg2[0] + '] Método no permitido: ' + method + '" >> ' + opt.bitacora + '/errors.log')
        # Imprimimos el request
        print ("from connected  user:\n" + str(data))
        # Cerramos la conexión del socket
        conn.close()


    

