<?php //echo $_SERVER['ROOT'];
/*
$bx = file_get_contents('body.xml');
//var_dump($bx);
echo $bx;
*/

/* Создание XML body с передаваемыми данными */ 

$bxml = '<soapenv:Body wsu:Id="body">';
$bxml .= '<ehd:setDataIn>';
$bxml .= '<xml><![CDATA[<message><id>123</id>';
$bxml .= '<catalogname="catalog">';
$bxml .= '<itemaction="added">';
$bxml .= '<categories>';
$bxml .= '<category nameHier="nameHierarchy">59</category>';
$bxml .= '</categories>';
$bxml .= '<data>';
$bxml .= '<attributefield_id="-2" type="INTEGER"pk="true">';
$bxml .= '<values>';
$bxml .= '<value occurrence="0">1</value>';
$bxml .= '</values>';
$bxml .= '</attribute>';
$bxml .= '<attribute field_id="557" type="DICT" pk="false">';
$bxml .= '<values>';
$bxml .= '<value occurrence="0">1</value>';
$bxml .= '</values>';
$bxml .= '</attribute>';
$bxml .= '<attribute field_id="559" type="DICT" pk="false">';
$bxml .= '<values>';
$bxml .= '<value occurrence="0">115</value>';
$bxml .= '</values>';
$bxml .= '</attribute>';
$bxml .= '<attributefield_id="558" type="STRING" pk="false"><values>';
$bxml .= '<value occurrence="0">TEST SERVICE2</value>';
$bxml .= '</values>';
$bxml .= '</attribute>';
$bxml .= '</data>';
$bxml .= '</item>';
$bxml .= '</catalog></message>]]></xml>';
$bxml .= '</ehd:setDataIn>';
$bxml .= '</soapenv:Body>';

/*
$xml = <body>xml</body>;
$dom_xml= new DomDocument();
$dom_xml->loadXML($xml); 
$path="body.xml";
echo $dom_xml->save($path);
*/


$file = 'body.xml';
// Создаем BODY файл
$current = file_get_contents($file);
// Добавляем содержимое в файл
$current = $bxml;
// Пишем содержимое в файл
file_put_contents($file, $current);


/* Проверка на существование файла */
$fileExists = file_exists("body.xml");
var_dump($fileExists);

/*
  $dom = new domDocument("1.0", "utf-8"); // Создаём XML-документ версии 1.0 с кодировкой utf-8
  $root = $dom->createElement("users"); // Создаём корневой элемент
  $dom->appendChild($root);
  $dom->save("users.xml"); // Сохраняем полученный XML-документ в файл
 echo $xml;
*/


/* Подключение к серверу */ 
$connect = ssh2_connect('37.140.199.15', 22);
ssh2_auth_password($connect, 'root', 'Haeghoov9che');

/* Подписываем body.xml */
$stream = ssh2_exec($connect, "cd /var/www/html && /opt/cprocsp/bin/amd64/cryptcp -pin 1234567 -sign -dn E=vladgplanet@gmail.com body.xml");

#stream_set_blocking($errorStream, true);
stream_set_blocking($stream, true);

#echo "Output: " . stream_get_contents($stream);
#echo "Error: " . stream_get_contents($errorStream);
stream_get_contents($stream);

#fclose($errorStream);
fclose($stream);


//$fileExists = file_exists("/var/www/html/body.xml.sig");
//var_dump($fileExists);



//$stream = ssh2_exec($connect, 'pwd');
//var_dump($stream);


/* Получаем содержимое файла в каноническом виде */
$bx = file_get_contents('body.xml.sig');
//echo $bx;


/* Создаем содержимое тега SignedInfo для подписание */
$sxml  = '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
$sxml .= '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>';
$sxml .= '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>';
$sxml .= '<ds:Reference URI="#body">';
$sxml .= '<ds:Transforms>';
$sxml .= '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>';
$sxml .= '</ds:Transforms>';
$sxml .= '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>';
$sxml .= '<ds:DigestValue>';
$sxml .= $bx; //Помещаем хеш тега BODY  
$sxml .= '</ds:DigestValue>';
$sxml .= '</ds:Reference>';
$sxml .= '</ds:SignedInfo>';


/* Создаем Файл для подписания тега SignedInfo */
$file = 'SignedInfo.xml';
file_get_contents($file);
// Добавляем содержимое в файл
$current = $sxml;
// Пишем содержимое в файл
file_put_contents($file, $current);


/* Подписсываем файл тега SignedInfo */
$stream = ssh2_exec($connect, 'cd /var/www/html');
$stream = ssh2_exec($connect, "cd /var/www/html && /opt/cprocsp/bin/amd64/cryptcp -pin 1234567 -sign -dn E=vladgplanet@gmail.com SignedInfo.xml");




#stream_set_blocking($errorStream, true);
stream_set_blocking($stream, true);

#echo "Output: " . stream_get_contents($stream);
#echo "Error: " . stream_get_contents($errorStream);
stream_get_contents($stream);

#fclose($errorStream);
fclose($stream);



/* Получаем содержимое SignedInfo в каноническом виде */
$si = file_get_contents('SignedInfo.xml.sig');
//echo $si;


//$pkey = file_get_contents('gost.req');
//echo $pkey;


/* Получаем открытый ключ */
$stream = ssh2_exec($connect, 'cd /root/test');
$pubkey = file_get_contents('key.pem');


/* Создаем заголовок SOAP */
$hxml  = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">';
$hxml .= '<soapenv:Header>';
$hxml .= '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soapenv:actor="Responder">';
$hxml .= '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
//
$hxml .= '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">';
$hxml .= '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>';
$hxml .= '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>';
$hxml .= '<ds:Reference URI="#body">';
$hxml .= '<ds:Transforms>';
$hxml .= '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>';
$hxml .= '</ds:Transforms>';
$hxml .= '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>';
$hxml .= '<ds:DigestValue>';
$hxml .= $bx;  //Помещаем хеш тега BODY  
$hxml .= '</ds:DigestValue>';
$hxml .= '</ds:Reference>';
$hxml .= '</ds:SignedInfo>';
//
$hxml .= '<ds:SignatureValue>';
$hxml .= $si;  //Помещаем хеш тега SignedInfo  
$hxml .= '</ds:SignatureValue>';
$hxml .= '<ds:KeyInfo>';
$hxml .= '<wsse:SecurityTokenReference>';
$hxml .= '<wsse:Reference URI="#CertId" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>';
$hxml .= '</wsse:SecurityTokenReference>';
$hxml .= '</ds:KeyInfo>';
$hxml .= '</ds:Signature>';
$hxml .= '<wsse:BinarySecurityToken xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="CertId">';
$hxml .= $pubkey; //Помещаем открытый ключ
$hxml .= '</wsse:BinarySecurityToken>';
$hxml .= '</wsse:Security>';
$hxml .= '</soapenv:Header>';



/* Создаем SOAP для передачи данных */
$xml = $bxml.$hxml;
//echo $xml;

//$stream = ssh2_exec($connect, '/usr/local/bin/php -i'); 

//$cmd = 'if test -d "/root/linux-amd64/gost.csr"; then echo 1; fi';
//$stream = ssh2_exec($connect, $cmd);

//$sftp = ssh2_sftp($connect);
//$fileExists = file_exists('ssh2.sftp://' . $sftp . '/root/linux-amd64/gost.csr');
//var_dump($fileExists);

//ssh2_exec($connect, "cryptcp -sign -dn E=vladgplanet@gmail.com ssh2.sftp://" . $sftp . "/root/linux-amd64/body.xml");
?>