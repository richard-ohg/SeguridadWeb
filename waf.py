import os, re, datetime

def getMethodAndQuery(request):
    patron = '(.*) (.*) HTTPS?\/.*'
    for x in request:
        mo = re.match(patron,x)
        if mo:
            return mo.groups()
    return "",""

def createAuditLog(file, ip_client, port_client, ip_dest, port_dest, id_rule, description, request):
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
    dic = {}
    spliteo = rule.split(";")
    # print(spliteo)
    dic['id_rule'] = spliteo[0].split('->')[1]
    dic['vars'] = spliteo[1].split('|')
    operator, expreg = ";".join(spliteo[2:-2]).split(':')
    # print(expreg[1:-1],end="\n\n")
    dic['expreg'] = operator,expreg[1:-1]
    dic['description'] = spliteo[-2]
    dic['accion'] = spliteo[-1].split(':')[-1]
    return dic

def readFile(file):
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
    if operator == 'iregex': 
        if re.search(pattern, string, re.I):
            return False
    else:
        if re.search(pattern, string):
            return False
    return True



def filterData(request, file_rules):
    arrayDict = readFile(file_rules)
    # Recorremos la lista que tiene diccionarios de las reglas
    for rule in arrayDict:
        for var in rule['vars']:
            arg = request.split('\r\n')
            # print(arg)
            operator,pattern = rule['expreg']
            if var == "METODO":
                method, query = getMethodAndQuery(arg)
                # print(method,query)
                # Checamos si evaluamos la expresión regular como iregex o regex
                if not checkPatternRegexOrIregex(operator, pattern, method):
                    return False
                # print(operator,pattern)
                print("Se aplicó la variable METODO en regla: ", rule['id_rule'])
            elif var == "RECURSO":
                if not checkPatternRegexOrIregex(operator, pattern, query):
                    return False
                print("Se aplicó la variable RECURSO en regla: ", rule['id_rule'])
            elif var == "AGENTE_USUARIO":
                pattern = 'User-Agent: {}'.format(pattern)
                if not checkPatternRegexOrIregex(operator, pattern, request):
                    return False
                print("Se aplicó la variable AGENTE-USUARIO en regla: ", rule['id_rule'])
            elif var == "CUERPO":
                body = request.split('\r\n\r\n')
                if not checkPatternRegexOrIregex(operator, pattern, body[-1]):
                    return False
                print("Se aplicó la variable CUERPO en regla: ", rule['id_rule'])
            elif var == "CLIENTE_IP":
                pattern = 'Host: {}'.format(pattern)
                if not checkPatternRegexOrIregex(operator, pattern, request):
                    return False
                print("Se aplicó la variable CLIENTE_IP en regla: ", rule['id_rule'])
            # elif var == "CABECERAS_VALORES":
            #     # Recorremos la lista que se creo con cada renglon de la petición
            #     for header in arg:
                    

            #     if not checkPatternRegexOrIregex(operator, pattern, request):
            #         return False
            #     print("Se aplicó la variable CABECERAS_VALORES en regla: ", rule['id_rule'])
            # elif var == "CABECERAS_NOMBRE":
            #     pattern = 'Host: {}'.format(pattern)
            #     if not checkPatternRegexOrIregex(operator, pattern, request):
            #         return False
            #     print("Se aplicó la variable CABECERAS_NOMBRE en regla: ", rule['id_rule'])
            
             

                

                

                    
        


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
Cookie: _xsrf=2|8bbbe995|26cc979cfff4e871672d656fe9871cb5|1550340508; username-localhost-8888="2|1:0|10:1550938954|23:username-localhost-8888|44:NmE1MmQ0ZmU4YmUxNGJmOGFhNDJiZTgyZWYzNWQ1N2I=|03a69f96c2b79be1b46793b14663ab61e0ec27f349a0d253d37dcbeb410ff293"\r
"""

    filterData(request,"reglas.txt")
    # print(readFile("reglas.txt"))

