Projeto de Redes de Computadores 2023/2024

Desenvolvido por Grupo 13:

    Alexandre Vudvud (ist number 103363)
    Dinis Caroço (ist number 103312)

Para executar o projeto, é necessario dar make na diretoria deste ficheiro.

Depois de fazer make, irão ser gerados dois executaveis - "user" e "AS", 
que correspondem ao executavel do user e ao executavel do servidor, respetivamente.

Para correr o servidor e user na mesma maquina, so é necessario de correr os executaveis. (./AS e ./user)

Argumentos que podem ser passados aos executaveis :

AS:
    Ao executar AS é possivel passar como argumento "-p PORT_NUMBER", onde o PORT_NUMBER é o numero do porto onde querem correr o servidor.
    Por default o numero do porto onde corre o servidor é 58013.

    Tambem é possivel passar "-v" como argumento, para ativar o modo verboso do server, neste modo o servidor irá imprimir as suas ações.

user:
    Ao  executar user é possivel passar dois argumentos "-n IP_ADDRESS" e "-p PORT_NUMBER", onde IP_ADDRESS é o indereço IP do servidor ao qual
    quere se ligar, e o PORT_NUMBER é o numero do porto onde o servidor corre.

    Por default user liga ao localhost no porto 58013.