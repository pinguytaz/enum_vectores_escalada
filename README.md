# enum_vectores_escalada

Modulo post (para linux aunque seguramente con muy poco cambios también es valido para MacOS) que realiza un pequeño análisis en
busca de posibles vectores de ataque para escalar privilegios tales como:
   * Información del Sistema operativo y versión de kernel
   * Identificación de usuario y grupos.
   * Posibilidad de escritura en ficheros passwd, groups y shadow
   * Versión sudo y si es podemos escribir en /etc/sudoers
   * Archivo con permisos SUID
   
