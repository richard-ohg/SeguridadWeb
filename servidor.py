import optparse
import socket
import os
import subprocess
import re
import datetime
import waf

list_content_type = {'txt':'text/plain',
'hmtl':'text/html',
'jpeg':'image/jpeg',
'png':'image/png',
'js':'text/javascript',
'zip':'application/zip',
'xml':'application/xml',
'mp4':'video/mp4',
'pdf':'application/pdf'}

html_response_200 = """
<h1> Bienvenido ;) </h1>
"""

html_response_403 = """
<h1> Error 403: Error en permisos del archivo </h1>
"""

html_response_404 = """
<h1> Error 404: Recurso no encontrado </h1>
"""

html_response_405 = """
<h1> Error 405: Método no permitido </h1>
"""

html_response_500 = """
<h1> Error 500: Error al ejecutar un script </h1>
"""

def options():
    '''
	    Función que permite agregar las banderas correspondientes para el uso del
	    programa ejecutado como script.
    '''
    parser = optparse.OptionParser()
    parser.add_option('-p','--port', dest='port', type=int, default=8080, help='Puerto del servidor.')
    parser.add_option('-d','--directory', dest='directory', default='.', help='Directorio a mostrar')
    parser.add_option('-b','--bitacora', dest='bitacora', default='.', help='Directorio para bitacora')
    opts,args = parser.parse_args()
    return opts

def changeDirectory(directory):
    '''
        Función para cambiarnos de directorio
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
    mySocket = socket.socket()
    mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mySocket.bind((host,port))
    mySocket.listen(1)
    return mySocket

def createResponse(codigo, msg, type, text):
    http_response = "HTTP/1.1 {} {}\r\n".format(codigo,msg)
    http_response += "Content-Type: {}\r\n".format(type)
    http_response += "Connection: close\r\n\r\n"
    http_response += text      
    return http_response

def fileContent(file):
    try:
        with open(file,'rb') as f:
            return str(f.read())
    except:
        # print("No existe el archivo")
        return False

def getNameFile(string):
    return string.split('/')[-1]

def getTypeFile(file):
    return file.split('.')[-1]

def getContentTypeFile(type_file):
    for key,value in list_content_type.items():
        if key == type_file:
            # print(value)
            return value
    # print("No encontró el tipo de dato, se pondrá txt por defecto")
    return list_content_type['txt']

def getCurrentDirectory():
    return os.getcwd().split('/')[-1]

def setEnviromentVar(dc_root, port_remote, host_remote, port, user_agent, method, host, cookie="", query="", http_referer=""):
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
    patron = 'User-Agent: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getCookie(request):
    patron = 'Cookie: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getHeaderHost(request):
    patron = 'Host: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getHttpReferer(request):
    patron = 'Referer: '
    patron_compile = re.compile(patron)
    for x in request:
        if re.match(patron,x):
            return patron_compile.sub('',x)
    return ""

def getPost(request):
    patron = '(.*)=(.*)'
    for x in request:
        mo = re.match(patron,x)
        if mo:
            return mo.group(2)
    return ""



if __name__ == "__main__":
    '''
        Función principal
    '''
    opt = options()
    if changeDirectory(opt.directory):
        print("Accediendo al directorio ", getCurrentDirectory())
    else:
         print("Se usó directorio actual: ", getCurrentDirectory())
    os.system('mkdir -p '+opt.bitacora)
    sock = createSocket(opt.port)
    while True:
        conn, addr = sock.accept()
        print ("Connection from: " + str(addr))
        data = conn.recv(1024).decode()
        if not data:
            break
        arg = data.split() 
        arg2 = data.split('\r\n')
        print(arg)
        print(arg2)
        user_agent = getUserAgent(arg2)
        cookie =  getCookie(arg2)
        method, query = waf.getMethodAndQuery(arg2)
        hostEnv = getHeaderHost(arg2)
        http_referer = getHttpReferer(arg2)
        print("\nHost: "+hostEnv+"\n")
        print("\nUser agent: "+user_agent+"\n")
        print("\nCookie: "+cookie+"\n")
        print("\nMetodo: "+method)
        print("\nQuery: "+query)
        print("\nHttp_referer: "+http_referer)
        name_file = getNameFile(query)
        type_file = getTypeFile(name_file)
        os.system('echo "' + addr[0] + ' ' + datetime.datetime.now().strftime("%x:%X") + ' ' + arg2[0] + ' 200 - ' + user_agent + '" >> ' + opt.bitacora +'/access.log')
        if method == 'GET':
            # user_agent = " ".join(arg2[5].split(':')[1:])
            # cookie = " ".join(arg2[9].split(':')[1:])
            if type_file == 'py' or type_file == 'php' or type_file == 'pl' or type_file == 'cgi':
                env = setEnviromentVar(str(os.getcwd()), str(addr[1]), str(addr[0]), str(opt.port), user_agent, method, hostEnv, cookie, query, http_referer)
                try:
                    with subprocess.Popen([name_file], stdout=subprocess.PIPE, env=env) as proc: 
                        # print(name_file)
                        conn.sendall(createResponse(200,'OK','text/html',proc.stdout.read().decode('utf-8')).encode('utf-8')) 
                except IOError:
                    os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:403] [client ' + arg2[0] + '] No tiene permisos: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
                    conn.sendall(createResponse(403,'FORBIDDEN','text/html',html_response_403).encode('utf-8'))
                except:
                    conn.sendall(createResponse(500,'INTERNAL SERVER ERROR','text/html',html_response_500).encode('utf-8'))
                    os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:500] [client ' + arg2[0] + '] Error al ejecutar: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
            else:  
                # Para cuando entre al navegador sin acceder a ningun recurso
                if query == '/':
                    conn.sendall(createResponse(200, 'OK', 'text/html', html_response_200).encode('utf-8'))
                else:
                    # Guardamos el contenido del archivo que se solicitó
                    content_type_value = getContentTypeFile(type_file)
                    file_cont = fileContent(name_file)
                    # Si existe el archivo
                    if file_cont:
                        conn.sendall(createResponse(200, 'OK', content_type_value, file_cont).encode('utf-8'))
                    else:
                        conn.sendall(createResponse(404,'NOT FOUND', 'text/html', html_response_404).encode('utf-8'))
                        os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:404] [client ' + arg2[0] + '] Recurso no encontrado: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')

        # Método HEAD
        elif method == 'HEAD':
            conn.sendall(createResponse(200, 'OK', 'text/html', html_response_200).encode('utf-8'))
        # Método POST
        elif method == 'POST':
            arg3 = data.split('\r\n\r\n')
            print(arg3)
            # query = getPost(arg3)
            query = arg3[-1]+'\n'
            print("\nQuery: " + query+'\n')
            env = setEnviromentVar(str(os.getcwd()), str(addr[1]), str(addr[0]), str(opt.port), user_agent, method, hostEnv, cookie,http_referer = http_referer)
            try:
                with subprocess.Popen(['post.cgi'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env) as proc: 
                    proc.stdin.write(query.encode('utf-8'))
                    proc.stdin.close()
                    conn.sendall(createResponse(200,'OK','text/html',proc.stdout.read().decode('utf-8')).encode('utf-8')) 
            except Exception as e:
                print(e)
                conn.sendall(createResponse(403,'FORBIDDEN','text/html',html_response_403).encode('utf-8'))
                os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:403] [client ' + arg2[0] + '] Error con permisos: ' + name_file + '" >> ' + opt.bitacora + '/errors.log')
        else:
            conn.sendall(createResponse(405,'METHOD NOT ALLOWED','txt',html_response_405).encode())
            os.system('echo ["' + datetime.datetime.now().strftime("%c") + '] [error:405] [client ' + arg2[0] + '] Método no permitido: ' + method + '" >> ' + opt.bitacora + '/errors.log')
            print("Método no usado")
       
        print ("from connected  user:\n" + str(data))
            
        # data = str(data).upper()
        # print ("sending: " + str(data))
        conn.close()


    

