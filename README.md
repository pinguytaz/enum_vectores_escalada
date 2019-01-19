# enum_vectores_escalada

Modulo post (para linux aunque seguramente con muy poco cambios también es valido para MacOS) que realiza un pequeño análisis en
busca de posibles vectores de ataque para escalar privilegios tales como:
  1. Información del Sistema operativo y versión de kernel
  
  Con la versión de Kernel podremos buscar posibles Vulnerabilidades.
  
  2. Identificación de usuario y grupos.
  
  Es importante conocer los grupos a los que pertenecemos, podria ser que ya tengamos altos privilegios.
  
  3. Posibilidad de escritura en ficheros passwd, groups y shadow
  
  Analiza los permisos de escritura (/etc/passwd, /etc/group y /etc/shadow) un fichero con permisos de escritura, nos podria permitir crear un nuevo usuario o cambiar la clave. Tengamos en cuenta que las claves estan por defecto en /etc/sahdow pero podemos meterla en paasswd.
  Se puede ver en https://www.pinguytaz.net/index.php/2018/06/21/escalar-privilegios-a-root-fichero-etc-passwd-2-3/
  
  4. Versión sudo y si es podemos escribir en /etc/sudoers
  
  Ademas de ver la versión del sudo y al igual que en la versión de sistema operativo podemos vuscar vulneravilidades.
  Si tenemos permisos de /etc/sudoers se puede cambiar la configuración.
  
  5. Archivo con permisos SUID
  
  Un fichero del usuario root con SUID nos permitiria ejecutar programas con permiso de root sin serlo.
  Puedes ver más en:
  https://www.pinguytaz.net/index.php/2018/06/23/escalar-privilegios-a-root-error-suid-3-3/
  
 
