# Defendiendo los servidores de Spartan Technologies de ataques informáticos

	Autor: Diego De Santiago (CTO)
	Publicado el: Martes 5 de Junio del 2018

En la mañana del 4 de Junio, al revisar los logs (registros) de los servidores de base de datos, existian conexiones simultáneas, con la zona horaria UTC, ya que cada registro de inicio de sesión estaba en una hora relativamente contigua, todo esto se efectuó en un fin de semana, en donde los servidores dejaron de ser revisados en un rango de 12 horas.

Lo más extraño es que cada conexión tenía una latencia de aproximadamente dos segundos, y se concluyó que se trataba de un ataque de *fuerza bruta* (ver Imagen 1.0), se llegó a la conclusión en base a la siguiente información:

1. La utilización del CPU subió un 5% más de lo esperado.
2. La cantidad memoria liberable (Freeable Memory) bajó 20 MB.
3. La taza de Rx era más alta que la de Tx: Esto quiere decir que hay más datos recibidos que enviados.
4. La cantidad de conexiones aumentó en un 50%.

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/1.jpg">
<p align="center">Imagen 1.0 - Logs del servidor de base de datos</p>
</p>

## Solucionando el problema

El principal motivo por el cual hicieron un ataque de fuerza bruta fue porque las las interfaces del servidor pertenecian a un PG (Parameter Group) que hacia público el puerto del servidor, haciendo binding con la dirección multicast (0.0.0.0/0), los pasos seguidos para solucionar el problema fueron los siguientes:

1. Restringir el acceso al servidor creando una red privada (VPN) con un PG compartido para que los componentes de la infraestructura puedan comunicarse de forma aislada, sin ser visibles al exterior o públicos.
2. Tunelizar la conexión con SSL implementando un algoritmo RSA-256 como estándar para las conexiones entrantes y salientes de la base de datos, con la finalidad de prevenir ataques MIM (Man In The Middle), haciendo imposible que puedan obtener las consultas SQL al servidor.
3. Restringir que el servidor de base de datos sea administrable desde la computadora que lo administra, simplemente usando un *curl ifconfig.me*


## Conociendo a los atacantes

Cuando se analizaron los logs se puedieron ver cientos de intentos de inicio de sesión efectuados en los servidores de Spartan Technologies, een ese momento se planteó lo siguiente:

- Si el endpoint (Public DNS Record) es privado, de que forma pudieron encontrarlo.
- Usaron algún tipo de herramienta para analizar la infraestructura, de que forma se puede saber cual es.

Después de que se parsearon y analizaron los logs al obtener todos los dominios del cual habian querido iniciar sesión en el servidor, se obtuvo el siguiente Host Name (imagen 2.0), la herramienta es conocida como **Stretchoid**

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/2.jpg">
<p align="center">Imagen 2.0 - Hostname de la herramienta para analiazar infraestructuras</p>
</p>

Al accesar al dominio principal, la vista que renderizó pedía los siguientes campos como: nombre, email de la persona a la que se le enviará el reporte, y un bloque de IPs para escanear subredes, ya que la mayoría de subredes de Amazon son parecidas, no resulta complejo escanear infraestructura al azar (imagen 3.0).

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/3.jpg">
<p align="center">Imagen 3.0 - Herramienta para analizar la infraestructura</p>
</p>

Analizando esta herramienta se percató de lo siguiente:

1. Usa JQuery para enviar solicitudes con AJAX y validar los campos en el frente.
2. Usa una misma ruta (/optout) con un método POST para hacer los análisis.
3. Renderiza el contenido del análisis con un tipo de contenido de hipertexto (text/html), al analizar la infraestructura.


Lo que está mal con esta herramienta es que su mecanismo de validación en el frente puede ser fácilmente pasado (bypass) haciendo una solicitud directa al servidor, además de que no usan un mecanismo de tiempo de espera (timeout) por cada solicitud, también no hacen uso de un mecanismo que valide la idempotencia de las solicitudes, si se usara todo esto sería prácticamente imposible hacer que se automatizaran los escaneos a cualquier infraestructura.

## Perfilando el atacante

Las direcciones IPs registradas después del escaneo de Stretchoid, se repetian de tres a cuatro veces, con los mismos usuarios, por lo cual se concluye que el atacante usa la herramienta para analizar infraestructura al azar y después automatiza los ataques con un patrón diferente, haciendo uso de diccionarios para las combinaciones usuario:contraseña comunes pero inseguras como root, admin, 1234, etc.

El proceso que sigue el atacante es el siguiente:

1. Obtener la información de una infraestructura al azar.
2. Mapear los servicios comunes de bases de datos, instancias en linux, etc.
3. Automatizar el inicio de sesión con diccionarios comunes.
4. Repetir indefinidamente, hasta encontrar una combinación válida.

## Minería de datos con los logs

Previamente se han hecho conjeturas de como funciona el ataque de fuerza bruta automatizado, al hacer minería de datos sobre los logs obtenidos de ese día, se usaron las siguientes herramientas:

1. Terminal de linux.
2. Docker para containerizar un servidor de base de datos.
3. SED para transformar la salida de texto.
4. GREP para buscar en los logs patrones.
5. AWK para parsear y procesar el texto de los logs.

**Creación servidor MySQL en docker**

```bash
	docker pull mysql:5.7
	docker tag mysql:5.7 mysql:latest
	docker run --name ss-server -e "MYSQL_PORT=3306,MYSQL_ROOT_PASSWORD=test" -d 3306:3306 mysql

	#se prueba el servidor de base de datos
	nc -vv 127.0.0.1 3306
```

**Analizar los datos**

```bash
	$gunzip 00000.gz
	$cat 00000 | grep -E ".*'[a-zA-Z_0-9-]+'@'[\.a-zA-Z_0-9-]+'.*" | wc -l
	6602
```

	Se obtuvieron 6602 intentos de inicio de sesión en ese día.

Se extrajeron las direcciones IP, hosts y nombres de usuario que usaron para intentar acceder a los servidores de Spartan Technologies como un [dump](https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/dumps/sessions.dump), por lo tanto se debe mapear toda la información, haciendo uso de pipes y streams.

```bash
	cat 00000 
		| grep -E ".*'[a-zA-Z_0-9-]+'@'[\.a-zA-Z_0-9-]+'.*" \
		| awk '{print $9}' \
		| awk -F '@' '{print $1,$2}' \
		| sed -s "s/'//g" > sessions.dump
```

En el comando anterior se filtran las conexiones registradas en los logs, para una combinación user@host y posteriormente se obtiene la misma cadena pero de un registro del tipo de inicio de sesión, por último se separa por el símbolo (@) el usuario del host para llenar un fichero que contiene todas las conexiones separadas por un espacio.

Para transformar los datos analizados a ser una tabla relacional se crea una base de datos temporal, con el servidor desplegado con Docker en el entorno de desarrollo local, y se importan los datos cargándolos de un archivo de texto plano.

```bash
	mysql -u root -h 127.0.0.1 -v -p <<EOF
	drop database if exists session_db;
	create database if not exists session_db
		character set utf8mb4
		collate utf8mb4_unicode_ci;

	use session_db;

	drop table if exists login_tries;
	create table login_tries (
		username char(20) not null,
		host char(50) not null
	);

	load data local infile "sessions.dump"
		into table login_tries
		fields terminated by " "
		lines terminated by '\n'
		(username, host)
	EOF
```

Al importar los datos desde el archivo DUMP, se procede a la manipulación y mapeo de los mismos haciendo uso del lenguaje SQL, quería saber que usuarios fueron los que se intentaron autenticar o iniciar sesión con más frecuencia (imagen 4.0):

```sql
	select username, count(*) as login_counts 
	    from login_tries 
	         group by username 
	         order by login_counts desc 
	    limit 10;
```

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/4.jpg">
<p align="center">Imagen 4.0 - Diez nombres de usuario más usados para autenticarse</p>
</p>

Tal como se esperaba el usuario que intentó iniciar sesión más veces fue el usuario root, con 4613 intentos de diferentes orīgenes, solamente esta investigación se enfoca en los hosts con más recurrencia para hacer una análisis de cada uno de ellos (imagen 5.0).

```sql
	select host, count(*) as host_tries 
	    from login_tries 
	        group by host 
	        order by host_tries desc 
	    limit 10;
```

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/5.jpg">
<p align="center">Imagen 5.0 - Diez hosts más usados para autenticarse</p>
</p>

	Algunas direcciones IPs encontradas en el análisis son de Rusia, Alemania, China y otros lugares.

Se hace una vista con la consulta previamente hecha:

```bash
	create view vw_host_tries as 
	    select host, count(*) as host_tries 
	        from login_tries 
	             group by host 
	             order by host_tries desc 
	        limit 10;
```

Por lo tanto se debe analizar cada host, con una consulta in-line usando la vista previamente creada através del cliente de MySQL en la terminal:

```bash
	mysql -u root -b "session_db" -N -s -e "select host from vw_host_tries" -p > ips.dump
```

Para analizar cada host, se procede a tomar el archivo dumo de las IPs del resultado de ejecución de la vista, con la siguiente línea de código:

```bash
	for ip in `cat ips.dump`
	;do
		nmap -sV -Pn $ip
	;done
```

El [análisis](https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/dumps/service-scan.dump) tardó más de diez minutos, pero se obtuvo el siguiente resultado:

1. 123.249.76.68 - Puertos cerrados
2. 111.73.46.169: Servidor (Windows OS)
3. 101.254.149.185: Servidor (Windows OS)
4. 114.64.248.197: Servidor (Windows OS)
5. 5.188.10.20: Servidor (Windows OS)
6. 5.188.10.9: Servidor (Windows OS)
7. 5.188.10.13: Servidor (Windows OS)
8. 5.188.10.16: Servidor (Windows OS)
9. 111.73.45.174: Servidor (Windows OS)
10. 111.73.46.27: Servidor (Windows OS)

En el resultado del análisis se pudieron obtener la información de los servicios todas las direcciones IPs, la cuestión es que todos corren en un servidor en windows, algunos tienen el puerto 80 abierto, y renderizan una vista diciendo que el servidor se encuentra en mantenimiento, además que funcionan con IIS/6.0 una versión vieja del servidor web de microsoft, que tiene muchas vulnerabilidades (imagen 6.0).

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/6.jpg">
<p align="center">Imagen 6.0 - Servidor web encontrado</p>
</p>

## Conclusión de la investigación

1. Los servidores son administrados por el puerto 3389 que maneja el servicio de administración de escritorio remoto.
2. Se establece una conexión inversa con el servidor principal, lo cual practicamente es indetectable, porque es la víctima la que abre el puerto.
3. Los ordenadores zombies reciben las mismas instrucciones.
4. El servidor principal es que tiene más puertos abiertos y un servidor FTP para montar sus archivos.

<p align="center">
<img src="https://raw.githubusercontent.com/spartan-technologies/eng-cs-bf-attack/master/img/7.jpg">
<p align="center">Imagen 7.0 - Esquema de distribución de Botnet</p>
</p>