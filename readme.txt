Jose Luis Mira Serrano


./Cracker [OPTIONS]

-size [Numero a introducir] : tamaño de la clave (en caso de no especificarse comprueba todos los caracteres de forma exponencial)
-f [Ruta al archivo a desencriptar]
-threads [Numero a introducir] : numero de hilos en los que se va a ejecutar el cracker

OPCIONES DE REDUCCION DEL ESPACIO DE CARACTERES ASCII (si no se especifica ninguna comprueba todos los caracteres imprimibles)

-num : caracteres numericos
-alpha : letras mayusculas y minusculas
-alphanum : letras y numeros
-lower : letras minusculas
-upper : letras mayusculas



ejemplo de ejecucion: ./Cracker -f ./hola.gpg -size 4 -threads 4 -lower
ejemplo de compilacion: g++ -o Cracker cracker.cpp -pthread

