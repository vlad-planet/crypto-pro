## Требования:

```php
CentOS  Red Hut Linux
Настроенный apache под php 7
Для корректной работы необходимо установить расширение PECL ssh2.
Добавить в PATH: /opt/cprocsp/bin/amd64/
Добавить stream_get_contents по аналогии с примером в: https://www.php.net/manual/en/function.ssh2-exec.php


## Linux установка и настройка cryptopro. Создание ключей, сертивиката + подписание XML документа

```php
// # yum install cryptopro-preinstall-4.0.0-alt3.x86_64.rpm
// # tar -xf /var/www/html/linux-amd64.tgz
// # yum install cprocsp-curl* lsb-cprocsp-base* lsb-cprocsp-capilite* lsb-cprocsp-kc1* lsb-cprocsp-rdr-64*
// # yum install lsb-cprocsp-ca-certs*
// # export PATH="$(/bin/ls -d /opt/cprocsp/{s,}bin/*|tr '\n' ':')$PATH"
// # cpconfig -license -view
// # csptest -keyset -verifycontext | sed -n 's/.* Ver:*\([0-9.]\+\).*/\1/p'
// # cpconfig -hardware reader -view
// # csptest -enum -info -type PP_ENUMREADERS | iconv -f cp1251
// # cpconfig -hardware rndm -view
// # cpconfig -defprov -view_type
// # cpconfig -defprov -view -provtype 80
// # csptest -keyset -provtype 80 -newkeyset -cont '\\.\HDIMAGE\test'
// # csptest -keyset -enum_cont -fqcn -verifyc | iconv -f cp1251
// # csptestf -keyset -container '\\.\HDIMAGE\test' -info
// # cryptcp -creatrqst -dn "список имён полей" -cont 'путь к контейнеру' <название_файла>.csr
// # cryptcp -creatrqst -dn "cn=Test User5,e=cas@altlinux.org" -cont '\\.\HDIMAGE\test' gost.csr
// # cryptcp -creatrqst -dn "CN=Vladislav,SN=Baslykov,G=Gennadevich,E=vladgplanet@gmail.com,SNILS=12279543265,INN=007730230585,C=RU,S=77 Москва,L=Москва,street=Чечерский пр-д 104 кв.92,O=МНН,OU=Секретариат по МНН,T=Программист,OGRN=1177746207000" -provtype 80 -nokeygen -cont '\\.\HDIMAGE\test' -certusage "1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.12" gost.req

// # cat gost.req
// # certmgr -list -file certnew.p7b
// # certmgr -inst -file certnew.p7b -store uRoot

// #cryptcp -verify body1.xml.sig head.xml

// #certmgr -inst -file gost.cer -cont '\\.\HDIMAGE\test

// # cd /var/www/html && /opt/cprocsp/bin/amd64/cryptcp -pin 1234567 -sign -dn E=vladgplanet@gmail.com body.xml

// # openssl smime -sign -in file.xml -signer cert.pem -inkey private.key -out file_signed.xml -outform PEM
```