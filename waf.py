import os, re, datetime

def getMethodAndQuery(request):
    '''
        Función para obtener el metodo y la query de un request

        :param request: petición que llegue al servidor
        :return: tupla con los grupos de la expresión regular, regresará el método y el recurso, si no lo encuentra, retornará cadenas vacias
    '''
    patron = '(.*) (.*) HTTPS?\/.*'
    for x in request:
        mo = re.match(patron,x)
        if mo:
            return mo.groups()
    return "",""

def createAuditLog(file, ip_client, port_client, ip_dest, port_dest, id_rule, description, request):
    '''
        Función para crear|escribir el archivo donde se guardarán las detecciones
        :param file: nombre del archivo
        :param ip_client: ip del cliente
        :param port_client: puerto del cliente
        :param ip_dest: ip del destino
        :param port_dest: puerto del destino
        :param id_rule: id de la regla que se empleó
        :param description: descripción de la regla
        :param request: petición que se hizo
    '''
    report = 'echo "\n------------------------------------------------------------------------------------------------\n\n[' + \
    datetime.datetime.now().strftime("%c") + \
    '] ip_client: {}' +\
    ' - port_client: {}' +\
    ' - ip_dest: {}' +\
    ' - port_dest: {}' +\
    ' - id_rule: {}' +\
    ' - description: {}' +\
    ' - request: {}' +\
    '" >> audit.log'.format(ip_client, port_client, ip_dest, port_dest, id_rule, description, request)
    os.system(report)

def getDictionaryRule(rule):
    '''
        Función para obtener un diccionario de las reglas del archivo
        :param rule: regla de detección
        :return: diccionario donde la clave será el qué parte de la regla es y la llave es el valor de esa parte
    '''
    dic = {}
    # Separamos la regla mediante ;
    spliteo = rule.split(";")
    # Agregamos los valores al diccionario
    dic['id_rule'] = spliteo[0].split('->')[1]
    dic['vars'] = spliteo[1].split('|')
    # Obtenemos el operador y la expresión regular, en caso de que la expresión contenga un punto y coma (;) manejamos unir todas esas separaciones en una
    operator, expreg = ";".join(spliteo[2:-2]).split(':')
    dic['expreg'] = operator,expreg[1:-1]
    dic['description'] = spliteo[-2]
    dic['accion'] = spliteo[-1].split(':')[-1]
    return dic

def readFile(file):
    '''
        Función para leer el archivo de las reglas
        :param file: nombre del archivo a leer
        :return: una lista en donde cada elemento es un diccionario obtenido de la función getDictionaryRule
    '''
    arrayDicc = []
    with open(file,'r') as f:
        # print(f.readlines())
        arrayRules = f.read().split('\n')
        # print(arrayRules)
        for x in arrayRules:
            arrayDicc.append(getDictionaryRule(x))
    # print(arrayDicc)
    return arrayDicc

def checkPatternRegexOrIregex(operator, pattern, string):
    '''
        Función para checar si evaluamos la expresión regular como iregex o regex
        :param operator: operador de la expresión regular con valor iregex o regex
        :param pattern: expesión regular a evaluar
        :param string: cadena que será evaluada
        :return: retorna True si hay una coincidencia con la expresión regular, False si no hay
    '''
    if operator == 'iregex': 
        if re.search(pattern, string, re.I):
            return True
    else:
        if re.search(pattern, string):
            return True
    return False

def getValueHeaders(request):
    '''
        Función para obtener un diccionario con clave como la cabecera y el valor como su contenido de dicha cabecera
        :param request: lista donde cada elemento será un renglón de la petición
        :return: diccionario de las cabeceras
    '''
    dic = {}
    for x in request:
        aux = x.split(":")
        # Manejamos el caso en que el contenido de alguna cabecera tengo punto y coma (;)
        dic[aux[0]] = "".join(aux[1:])      
    return dic


def filterData(request, file_rules):
    '''
        Función para filtrar el request
        :param request: petición que le hacen al servidor
        :param file_rules: archivo que contendrá las reglas a evaluar
        :return: False si se encontró coincidencia con el archivo de reglas, request si la petición no tiene ningun problema
    ''' 
    # Leemos el archivo y guardamos la lista de diccionarios de las reglas
    arrayDict = readFile(file_rules)
    # Recorremos cada regla de la lista 
    for rule in arrayDict:
        # Recorremos las variables por si son más de una 
        for var in rule['vars']:
            # Separamos la petición cada salto de línea
            arg = request.split('\r\n')
            # Obtenemos el operador y el patrón de la sección expresión regular de la regla
            operator,pattern = rule['expreg']

            # if-else para ver que variables es y hacer lo correspondiente
            # Checamos el método
            if var == "METODO":
                # Obtenemos el método de la petición spliteada
                method, query = getMethodAndQuery(arg)
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, method):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable METODO en regla: ", rule['id_rule'])
            # Checamos el recurso
            elif var == "RECURSO":
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, query):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable RECURSO en regla: ", rule['id_rule'])
            elif var == "AGENTE_USUARIO":
                # Generamos la expresión regular
                pattern = 'User-Agent: {}'.format(pattern)
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, request):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable AGENTE-USUARIO en regla: ", rule['id_rule'])
            # Checamos en el cuerpo de la petición
            elif var == "CUERPO":
                # Separamos la petición en las cabeceras y el cuerpo
                body = request.split('\r\n\r\n')
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, body[-1]):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable CUERPO en regla: ", rule['id_rule'])
            # Checamos en el host de la petición
            elif var == "CLIENTE_IP":
                # Generamos la expresión regular
                pattern = 'Host: {}'.format(pattern)
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, request):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable CLIENTE_IP en regla: ", rule['id_rule'])
            # Checamos en la primera línea de la petición
            elif var == "PETICION_LINEA":
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, arg[0]):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable PETICION_LINEA en regla: ", rule['id_rule'])
            # Checamos en las cookies de la petición
            elif var == "COOKIES":
                # Generamos la expresión regular
                pattern = 'Cookie: {}'.format(pattern)
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, request):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable COOKIES en regla: ", rule['id_rule'])
            # Checamos en todas las cabeceras de la petición
            elif var == "CABECERAS":
                # Separamos entre los heards y el cuerpo de la petición
                headers = request.split('\r\n\r\n')
                # Checamos si evaluamos la expresión regular como iregex o regex
                if checkPatternRegexOrIregex(operator, pattern, headers[0]):
                    # Retornamos False en caso de que haya coincidencia
                    return False
                print("Se aplicó la variable CABECERAS en regla: ", rule['id_rule'])       
            # Checamos en los valores de las cabeceras de la petición
            elif var == "CABECERAS_VALORES":
                # Obtenemos un diccionario de las cabeceras de la petición
                headers = getValueHeaders(arg)
                # Recorremos ese diccionario obteniendo su llave,valor
                for header,value in arg.items():   
                    # Checamos si evaluamos la expresión regular como iregex o regex
                    if checkPatternRegexOrIregex(operator, pattern, value):
                        # Retornamos False en caso de que haya coincidencia
                        return False
                print("Se aplicó la variable CABECERAS_VALORES en regla: ", rule['id_rule'])
            elif var == "CABECERAS_NOMBRES":
                # Obtenemos un diccionario de las cabeceras de la petición
                headers = getValueHeaders(arg)
                # Recorremos ese diccionario obteniendo su llave,valor
                for header,value in arg.items():   
                    # Checamos si evaluamos la expresión regular como iregex o regex
                    if not checkPatternRegexOrIregex(operator, pattern, header):
                        # Retornamos False en caso de que haya coincidencia
                        return False
                print("Se aplicó la variable CABECERAS_NOMBRES en regla: ", rule['id_rule'])
    # Retornamos el request en caso de que no haya tenido ningún problema
    return request
                




if __name__ == "__main__":
    
    # createAuditLog("audit.log","192.168.1.1","1234","192.168.1.2","4321",'1','Bloqueo de método TRACE de HTTP','fooooooooo')

    request = """GET / HTTP/1.1\r
Host: localhost:8080\r
Connection: keep-alive\r
Purpose: prefetch\r
Upgrade-Insecure-Requests: 1\r
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r
Accept-Encoding: gzip, deflate, br\r
Accept-Language: es-ES,es;q=0.9\r
Cookie: _xsrf=2|8bbbe995|26cc979cfff4e871672d656fe9871cb5|1550340508; username-localhost-8888="2|1:0|10:1550938954|23:username-localhost-8888|44:NmE1MmQ0ZmU4YmUxNGJmOGFhNDJiZTgyZWYzNWQ1N2I=|03a69f96c2b79be1b46793b14663ab61e0ec27f349a0d253d37dcbeb410ff293"\r\n\r\n"""

    filterData(request,"reglas.txt")
    getValueHeaders(request.split('\r\n'))
    # print(readFile("reglas.txt"))

