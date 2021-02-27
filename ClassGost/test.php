<?php
include('ClassGost.php');

/** Реализация шифрования ГОСТ 28147-89 на основе
 * проверочного примера из ГОСТ Р 34.11-94 (Приложение А)
 *
 * Выполнение данного примера должно вернуть
 * 32bc0b1b 42abbcce
 * Что соответствует результату из Приложения А.
 *
 * @author IntSys
 * @copyright Copyright (c) 2011-2012, IntSys, intsystem.org
 */

/** Преобразовать строку в HEX представление
 *
 * @param string $str
 * @return string
 */
function str2hex($str){
	$hex=bin2hex($str);
	return implode(' ', str_split($hex, 8));
}

/** Получить строку из HEX представления строки
 *
 * @param string $hex
 * @return string
 */
function hex2str($hex){
	$hex=preg_replace('#\s+#si', '', $hex);
	$str='';

	for($i=0, $x=strlen($hex); $i<$x; $i+=2){
		$str.=chr(hexdec(substr($hex, $i, 2)));
	}

	return $str;
}

/** Таблица замен */
$code_table=array(
	array(4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
	array(14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
	array(5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
	array(7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
	array(6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
	array(4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
	array(13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
	array(1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
);

/** Ключ шифрования */
$code_key=array(
	0x733D2C20,
	0x65686573,
	0x74746769,
	0x79676120,
	0x626E7373,
	0x20657369,
	0x326C6568,
	0x33206D54
);

/** Шифруемые данные */
$code_data=hex2str('00000000 00000000');

//Ключи в приложении А из ГОСТ Р 34.11-94 даны в обратном порядке
$code_key=array_reverse($code_key);

$object=new ClassGost();
$object->SetTableReplace($code_table);
$object->SetKey($code_key);

$result=$object->Encode($code_data);

echo(var_dump(str2hex($result)));