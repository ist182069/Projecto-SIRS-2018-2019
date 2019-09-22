# Code

Nesta pasta apresentamos o código da aplicação. 

Esta aplicação foi decidida realizar na linguagem Python 2.7 depois de nos debatermos fortemente sobre quais as linguagens a utilizar. 
Embora Java fosse uma das nossas ideias para a concepção do Remote Document Access, devido a existir bastantes informações na web acerca das funcionalidades da linguagem e também como usar os vários pacotes de segurança e comunicações em rede da Oracle e da Sun, acabamos por escolher Python devido à sua versatilidade, ser uma linguagem leve, capacidade de importar facilmente múltiplos pacotes de segurança e comunicações cutting-edge simples de utilizar, ao rápido desenvolvimento de scripts nesta linguagem entre outras inúmeras razões. 
Com o Python, usamos também JSON para codificar a informação que é transferida entre máquinas pois JSON é um standard leve, versátil e organizado, facilmente usado com Python. 
Para as comunicações entre computadores usamos sockets que foram wrapped com SSL em ambos os lados da rede de forma a garantir comunicações seguras entre os integrantes. 
A utilização de sockets e não uma framework que facilite a comunicaçã deveu-se ao facto de assim controlarmos num nível muito baixo a informação e pelo facto dessas frameworks, que não serão nomeadas, serem bastante bloated o que fazem a aplicação ficar bastante lenta.

Apresentamos em cada um dos directórios os seguintes ficheiros:
- server-side: 
  - ficheiro ".py" com o código do servidor;
  - directório "server" com o certificado e chave do servidor;
  - scripts ".sh" para certificação de chaves;
  - directório "clients" com os certificados e ficheiros partilhados entre clientes;
  - directório "confs" com configurações e "requirements.txt" com os requisitos para correr a aplicação;
- client-side: 
  - ficheiro ".py" com o código do cliente;
  - directório "utils" com utilidades para a aplicação;
  - directórios "myfiles" e "mysharedfiles" onde respectivamente teremos os nossos ficheiros carregados e os ficheiros que partilhados;
  - "requeriments.txt" com os requisitos para correr a aplicação;
