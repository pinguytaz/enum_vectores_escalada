################################################################################
#  Fco. Javier Rodriguez Navarro 
#  https://www.pinguytaz.net
#
#  enum_vectores_escalada.rb:  Modulo Post para Metaesploit que realiza una 
#                              enumeración de posibles vectores de Escalada de
#                              privilegios.
#  use post/linux/gather/enum_vectores_escalada
#
#  Historico:
#     - 15 de Enero de 2019  V1  Version para curso CHEE
#
#  Librerias y enlaces de información
#  https://rapid7.github.io/metasploit-framework/api/
################################################################################
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
################################################################################
require 'msf/core'

class MetasploitModule < Msf::Post   # Herencia de modulo Explotación.
   include Msf::Post::File            
   include Msf::Post::Linux::System
   include Msf::Post::Linux::Priv

   def initialize(info = {})
     super(update_info(info,
       'Name'         => 'Información de posibles vectores escalada privilegios',
       'Description'  => %q{
         Este modulo recoge información de posibles vectores y ayudas para escalar privilegios:
              Info: Sistema operativo y versión de kernel
              Permisos ficheros passwd, groups shadow
              Versión sudo y si es del grupo
              Archivo con permisos SUID
       },
       'License'      => MSF_LICENSE,
       'Author'       => ['Fco. Javier Rodriguez Navarro'],
       'Platform'     => ['linux'],
       'SessionTypes' => ['shell', 'meterpreter']
     ))
   
   register_options(
     [
       OptString.new('SALIDA', [ false, 'Fichero de salida' ]),
     ], self.class)
   end   # Fin del constructor inicialize

   def run
      losgrupos = {}  # Se tendran los grupos del usuario.
      miusuario = "VACIO"

      salida = "Información Sistema / Usuario\n"
      tempo, miusuario = info_sistema(losgrupos) # Obtenemos información del sistema Kernel y usuario.
      salida = salida + tempo

      if is_root?  # Si ya se es Root, no es necesario buscar vectores de escala.
         print_error("Ya se es super usuario no es necesario escalar")
         salida = salida + "\n" + "El usuario es root (maximos privilegios)"
      else
         # Analisis de ficheros de los usuarios: passwd, group, shadow
         salida = salida +"\n\nVectores escalado Fich. gestion usuarios con permiso escritura \n"
         salida = salida + es_escritura("/etc/passwd",losgrupos,miusuario) 
         salida = salida + es_escritura("/etc/group",losgrupos,miusuario) 
         salida = salida + es_escritura("/etc/shadow",losgrupos,miusuario) 

         # Analisis de SUDO
         salida = salida +"\n\nVectores escalado SUDO\n"
         salida = salida + info_sudo(losgrupos,miusuario) # Version de SUDO y si el usuario esta en el grupo.

         # Analisis de ficheros con permisos SUID
         salida = salida + info_suid() # Localiza ficheros con SUID
      end 

      # Confirmamos si se debe o no grabar la información en fichero
      #print_status (datastore['SALIDA'])
      if (datastore['SALIDA'] != nil )
         print_status("Se salva resultado a " + datastore['SALIDA'])
         File.open(datastore['SALIDA'], 'w') do |fp|
            fp.puts salida
         end
      else
         print_status("No se Salva")
      end
   end  # Fin de run

   ##############################################################################
   # info_sistema(grupos): 
   #             Da la información del sistema de la session y usuario.
   # Param:
   #      grupos: Grupos del usuario que se obtienen de información.
   #
   # Retorno: Cadena indicando el resultado.
   #          Usuario que se obtiene.
   ##############################################################################
   def info_sistema(losgrupos)
      print_status('Informacion del sistema/usuarios:')

      kernel_version = cmd_exec("uname -a")
      sistema = "KERNEL: #{kernel_version}\n"
      print_good(sistema)

      # Obtenemos información del usuario de la sesion.
      id_usu = cmd_exec("id")

      # Obtenemos UID y GUID
      miuid = /uid=(\d*)\(([0-9a-z]*)\)/.match(id_usu)  # Obtenemos uid con el ID y el nombre
      migid = /gid=(\d*)\(([0-9a-z]*)\)/.match(id_usu)  # Obtenemos gid con el ID y el nombre
      usuario = "UID:#{miuid[1]} - #{miuid[2]} GID:#{migid[1]} - #{migid[2]}"
      
      elusuario = miuid[2]
      print_good(usuario)

      # Obtenemos la información de los grupos
      grupos = /\S* \S* \S*=(\S*)/.match(id_usu) # Obtenemos los datos de grupos
      patron=/(?:(\d*)\(([0-9a-z]*)\))/
      misgrupos = grupos[1].scan(patron)
      sgrupos= "GRUPOS: "
      misgrupos.each  do | i |
	 losgrupos[i[1]]=i[0] 
	 sgrupos = sgrupos + i[0] + "-" + i[1] + "  "
      end
      print_good(sgrupos)

      retorno =  sistema + "\n" + elusuario + "\n" +sgrupos + "\n"
      return retorno, elusuario
   end # Fin de info_sistema


   ##############################################################################
   # es_escritura(fichero,grupos,usuario): 
   #           Mira si el fichero tiene permisos de escritura con ese usuario
   #
   # Param:
   #      fichero: Nombre del fichero a examinar.
   #      grupos: Grupos del usuario.
   #      usuario: Usuario del que se miran los permisos de escritura.
   #
   # Retorno: Cadena indicando el resultado.
   ##############################################################################
   def es_escritura(fichero,losgrupos,usuario)

      elretorno = "Fichero " + fichero
      print_status(elretorno)

      f_passwd = cmd_exec("ls -l "+fichero)
      datos = /(..........) . ([0-9a-z]*) ([0-9a-z]*)/.match(f_passwd)

      # Comprobación escritura de usuario.
      if (datos[2] == usuario and datos[1][2]=='w')
         tmp = "Usuario con permiso de escritura en " + fichero
         print_good(tmp)
         elretorno = elretorno + "\n" + tmp
      end

      # Comprobacion de escritura para grupo
      if (losgrupos[datos[3]] != nil  and datos[1][5]=='w')
         tmp = "Usuario con permiso en el grupo " + datos[3]+ " de "+ fichero
         print_good(tmp)
         elretorno = elretorno + "\n" + tmp
      end

      # Comprobacion de escritura para todos
      if (datos[1][8]=='w')
         tmp = "Cualquiera puede escribir en " + fichero
         print_good(tmp)
         elretorno = elretorno + "\n" + tmp
      end
      
      return elretorno
   end  # FIN metodo es_escritura


   ##############################################################################
   # info_sudo(grupos,usuario):  
   #       Da de los permiso y quien de sudo, asi como version
   #
   # Param:
   #      grupos: Grupos del usuario.
   #      usuario: Usuario del que se miran los permisos de escritura.
   #
   # Retorno: Cadena indicando el resultado.
   ##############################################################################
   def info_sudo(losgrupos,usuario)
      print_status('Vector escaldado SUDO:')
      sudo = cmd_exec("sudo -V")

      if losgrupos["sudo"] != nil
         essudo = "Suceptible ataque con SUDO"
         print_good(essudo)
      else
         essudo = "En principio no pertenece a grupo SUDO"
         print_error(essudo)
      end

      salida = "Version de Sudo:\n#{sudo}"
      print_status(salida)

      salida = salida + es_escritura("/etc/sudoers",losgrupos,usuario)

      return "\n" + essudo + "\n" + salida + "\n"
   end # Fin de info_sudo



   ##############################################################################
   # info_suid():  Da de los permiso y quien de sudo, asi como version
   ##############################################################################
   def info_suid()
      salida ="Vectores de escalado permisos SUID"
      print_status(salida)
      find = cmd_exec("find / -perm -u=s -type f 2> /dev/null")
      print_good(find)

      salida = salida + find
      return salida

   end # FIN info_SUID

end #FIn de clase

