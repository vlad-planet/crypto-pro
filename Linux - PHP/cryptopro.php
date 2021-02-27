<?php
$connect = ssh2_connect('37.140.199.15', 22);
ssh2_auth_password($connect, 'root', 'Haeghoov9che');

$stream = ssh2_exec($connect, "cd /var/www/html && /opt/cprocsp/bin/amd64/cryptcp -pin 1234567 -sign -dn E=vladgplanet@gmail.com body.xml");
#$errorStream = ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);

#stream_set_blocking($errorStream, true);
stream_set_blocking($stream, true);

#echo "Output: " . stream_get_contents($stream);
#echo "Error: " . stream_get_contents($errorStream);
stream_get_contents($stream);

#fclose($errorStream);
fclose($stream);

$fileExists = file_exists("/var/www/html/body.xml.sig");
var_dump($fileExists);
?>
