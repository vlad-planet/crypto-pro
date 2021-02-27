<?php

/** Класс осуществляющий работу с шифром ГОСТ 28147-89 (шифрование/дешифрованние данных)
 *
 * @author IntSys
 * @copyright Copyright (c) 2011-2013, IntSys, intsystem.org
 */
class ClassGost{
	/** Количесто иттераций основного шага криптообразования
	 */
	const CNT_MAIN_STEP=32;

	/** Таблица замен
	 *
	 * @var array
	 */
	protected $s_block=array(
		array(6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2),
		array(14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9),
		array(13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12),
		array(7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3),
		array(1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12),
		array(4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3),
		array(4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14),
		array(5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11),

	);

	/** Ключ
	 *
	 * @var array
	 */
	protected $k_block=array (
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
	);


	/** Зашифровать данные
	 *
	 * @param string $data данные для шифрования
	 * @param mixed $key ключ шифрования
	 * @param array $table таблица замен
	 * @return mixed возвращает зашифрованную строку, или false в случае неудачи
	 */
	function Encode($data, $key=null, $table=null){
		if(!is_null($key)){
			if(!$this->SetKey($key)){
				return false;
			}
		}

		if(!is_null($table)){
			if(!$this->SetTableReplace($table)){
				return false;
			}
		}

		$blocks=$this->LoadData2Blocks($data);
		$keys=$this->LoadKeysArray(self::CNT_MAIN_STEP);

		$result='';

		foreach($blocks as $block){
			$result.=$this->Global_MainStep($block, $keys);

		}

		return $result;
	}

	/** Расшифровать данные
	 *
	 * @param string $data зашифрованные данные
	 * @param mixed $key ключ шифрования
	 * @param array $table таблица замен
	 * @return mixed возвращает исходные данные, или false в случае неудачи
	 */
	function Decode($data, $key=null, $table=null){
		if(!is_null($key)){
			if(!$this->SetKey($key)){
				return false;
			}
		}

		if(!is_null($table)){
			if(!$this->SetTableReplace($table)){
				return false;
			}
		}

		$blocks=$this->LoadData2Blocks($data);
		$keys=array_reverse($this->LoadKeysArray(self::CNT_MAIN_STEP));

		$result='';
		foreach($blocks as $block){
			$result.=$this->Global_MainStep($block, $keys);
		}

		return $result;
	}

	/** Установить ключ шифрования<br><br>
	 * Возможно указать ключ в двух форматах:<br>
	 *  - Строка длинной в 32 байта<br>
	 *  - Массив из 8 элементов, где каждый элемент - 4 байтовое число integer<br><br>
	 * При этом любое отклонение от данных форматов будет вызывать ошибку
	 *
	 * @param mixed $key ключ шифрования
	 * @return boolen возвращает true если удалось установить ключ шифрования, false - если произошла ошибка
	 */
	function SetKey($key){
		if(is_string($key)){
			if(strlen($key)!==32){
				trigger_error(__METHOD__.': "$key" length must be equal to 256 bits (32 bytes)', E_USER_WARNING);
				return false;
			}

			$new_key=array();
			for($i=0; $i<32; $i+=4){
	//			$tmp=(int)hexdec(bin2hex(substr($key, ($i*4), 4)));
				$tmp=(int)hexdec(bin2hex(substr($key, ($i), 4)));
				$new_key[]=$tmp;
			}

			$this->k_block=$new_key;
			return true;
		}elseif(is_array($key)){
			if(count($key)!=8){
				trigger_error(__METHOD__.': count of elements in the array "$key" must be equal to 8', E_USER_WARNING);
				return false;
			}
			$new_key=array();
			foreach($key as $k => $val){
				if(!is_integer($val)){
					trigger_error(__METHOD__.': every element of the array "$key" must be integer. The array element "$table['.htmlspecialchars($k).']" is not an integer.', E_USER_WARNING);
					return false;
				}

				$new_key[]=$val;
			}

			$this->k_block=$new_key;
			return true;
		}else{
			trigger_error(__METHOD__.': unknown "$Key" format. "$key" must be array[8] of integer or 32-bytes string.', E_USER_WARNING);
			return false;
		}
	}

	/** Установить таблицу замен.<br>
	 * Формат таблицы замен - матрица размерностью 8x16,
	 * каждый ее элемент больше либо равен 0 и меньше либо равен 15,
	 * при этом в каждой строке не должно быть повторяющихся значений.<br><br>
	 * Также обратите внимание что неправильный выбор таблицы замен, может
	 * привести к снижению стойкости шифра.
	 *
	 * @example
	 * Пример таблицы:<br>
	 * array(6 ,12,7 ,1 ,5 ,15,13,8 ,4 ,10,9 ,14,0 ,3 ,11,2 ),<br>
	 * array(14,11,4 ,12,6 ,13,15,10,2 ,3 ,8 ,1 ,0 ,7 ,5 ,9 ),<br>
	 * array(13,11,4 ,1 ,3 ,15,5 ,9 ,0 ,10,14,7 ,6 ,8 ,2 ,12),<br>
	 * array(7 ,13,10,1 ,0 ,8 ,9 ,15,14,4 ,6 ,12,11,2 ,5 ,3 ),<br>
	 * array(1 ,15,13,0 ,5 ,7 ,10,4 ,9 ,2 ,3 ,14,6 ,11,8 ,12),<br>
	 * array(4 ,10,9 ,2 ,13,8 ,0 ,14,6 ,11,1 ,12,7 ,15,5 ,3 ),<br>
	 * array(4 ,11,10,0 ,7 ,2 ,1 ,13,3 ,6 ,8 ,5 ,9 ,12,15,14),<br>
	 * array(5 ,8 ,1 ,13,10,3 ,4 ,2 ,14,15,12,7 ,6 ,0 ,9 ,11),<br>
	 *
	 * @param array $table таблица замен
	 * @return boolean возвращает true если удалось установить таблицу замен, false- если произошла ошибка
	 */
	function SetTableReplace($table){
		if(!is_array($table)){
			trigger_error(__METHOD__.': "$table" must be array', E_USER_WARNING);
			return false;
		}

		if(count($table)!=8){
			trigger_error(__METHOD__.': count of elements in the array "$table" must be equal to 8', E_USER_WARNING);
			return false;
		}

		$i=0;
		$new_array=array();
		foreach($table as $key => $val){
			if(!is_array($val)){
				trigger_error(__METHOD__.': $table['.htmlspecialchars($key).'] must be array', E_USER_WARNING);
				return false;
			}

			if(count($val)!=16){
				trigger_error(__METHOD__.': count of elements in the array "$table['.htmlspecialchars($key).']" must be equal to 16', E_USER_WARNING);
				return false;
			}


			$new_val=array();
			foreach($val as $int_key => $int_val){
				if(!is_integer($int_val)){
					trigger_error(__METHOD__.': every element of the array "$table['.htmlspecialchars($key).']" must be integer. The array element "$table['.htmlspecialchars($key).']['.htmlspecialchars($int_key).']" is not an integer.', E_USER_WARNING);
					return false;
				}

				if($int_val>15 || $int_val<0){
					trigger_error(__METHOD__.': every element of the array "$table['.htmlspecialchars($key).']" must be greater than or equal to 0 and less than or equal to 15. The array element "$table['.htmlspecialchars($key).']['.htmlspecialchars($int_key).']" is not in this range.', E_USER_WARNING);
					return false;
				}
				$new_val[]=$int_val;
			}

			$new_array[$i]=$new_val;
			$i++;
		}


		$this->s_block=$new_array;
		return true;
	}

	/** Основной шаг шифрообразования
	 *
	 * @param string $block шифруемый блок
	 * @param array $keys подготовленный массив с ключами
	 * @param intger $cnt_repeat [опционально] количество преобразований
	 * @return string
	 */
	protected function Global_MainStep($block, $keys, $cnt_repeat=self::CNT_MAIN_STEP){
		$this->Global_BlockExplode($block, $n1, $n2);

		if(count($keys)<$cnt_repeat){
			$cnt_repeat=count($keys);
		}

		for($i=0; $i<$cnt_repeat; $i++){
			$val=$this->Global_SummMod32($n1, $keys[$i]);

			$val=$this->Global_BlockReplace($val);

			$val=$this->Global_BlockCycleShift($val, 21);

			$val=$val ^ $n2;

			$n2=$n1;
			$n1=$val;
		}

		$this->Global_BlockImplode($block, $n2, $n1);
		return $block;
	}

	/** Функция цикличного побитового сдвига вправо
	 *
	 * @param integer $block
	 * @param integer $bits количество битов для сдвига
	 * @return integer
	 */
	protected function Global_BlockCycleShift($block, $bits){
		if($bits>0){
			$a=$bits;
			$b=32-$a;
			$block=(($block >> $a) & ~(-pow(2,$b)))^($block << $b);
		}
		return $block;
	}

	/** Замена по таблице замен
	 *
	 * @param integer $block текущий блок для замены
	 * @return integer
	 */
	protected function Global_BlockReplace($block){
		$new_block=0;

		for($i=0; $i<8; $i++){
			//Вычленяем нужные 4 бита под замену
			$rem=$block>>(4*($i+1));
			$rem=$rem<<(4*($i+1));

			if($i==7){
				$hex=$rem;
			}else{
				$hex=$block-$rem;
				$block=$rem;
			}

			$hex=$this->Global_BlockCycleShift($hex,(4*$i));

			//Находим на какое число его заменять по таблице замен
			$replace=$this->s_block[$i][$hex];

			//Заменяем
			$new_block=$new_block + (pow(16, $i)*$replace);
		}

		return $new_block;
	}

	/** Суммирование двух чисел по модулю 32
	 *
	 * @param integer $bin1 число (4 байта)
	 * @param integer $bin2 число (4 байта)
	 * @return integer результат вычисления (4 байта)
	 */
	protected function Global_SummMod32($bin1, $bin2){
		$summ=$this->NormalizeInteger32(intval($bin1 + $bin2));

		return $summ;
	}

	/** Разбиение блока на "правую" и "левую" часть
	 *
	 * @param string $block входной блок (8 байт)
	 * @param &integer $left левая часть (накопитель N1) (4 байта)
	 * @param &integer $right правая часть (накопитель N2) (4 байта)
	 */
	protected function Global_BlockExplode($block, &$left, &$right){
		$left='';
		$right='';

		$left=substr($block, 0, 4);
		$right=substr($block, 4, 4);

		$left =hexdec(bin2hex($left ));
		$right=hexdec(bin2hex($right));
	}

	/** Разбиение блока на "правую" и "левую" часть
	 *
	 * @param &string $block входной блок (8 байт)
	 * @param integer $left левая часть (накопитель N1) (4 байта)
	 * @param integer $right правая часть (накопитель N2) (4 байта)
	 */
	protected function Global_BlockImplode(&$block, $left, $right){
		$left =sprintf("%08x", $left );
		$right=sprintf("%08x", $right);

		$block='';

		$arr=str_split($left, 2);
		foreach($arr as $hex){
			$block.=chr(hexdec($hex));
		}

		$arr=str_split($right, 2);
		foreach($arr as $hex){
			$block.=chr(hexdec($hex));
		}
	}

	/** Генерируем массив с ключами
	 *
	 * @param integer $cnt_repeat количество ключей
	 * @return array
	 */
	protected function LoadKeysArray($cnt_repeat=self::CNT_MAIN_STEP){
		$key_block=array();
		for($i=0; $i<$cnt_repeat; $i++){
			if($i<($cnt_repeat-8)){
				$x=$i % 8;
			}else{
				$x=7 - ($i % 8);
			}
			$key_block[]=$this->k_block[$x];
		}

		return $key_block;
	}

	/** Разбиваем данные на блоки по 64 бита (8 байт)
	 *
	 * @param string $data входные данные
	 * @param integer $block_size [опционально] (64 - дефолт) размерность блоков
	 * @return array выходной массив с блоками
	 */
	protected function LoadData2Blocks($data, $block_size=64){
		$blocks=array();

		$block_len=(int)$block_size / 8;

		for($i=0, $x=(ceil(strlen($data)/$block_len)); $i<$x; $i++){
			$blocks[$i]=substr($data, ($i*$block_len), $block_len);

			if($i==($x-1)){
				//Если последний блок не полон, то дополняем его нулями
				$blocks[$i]=str_pad($blocks[$i], $block_len, chr(0), STR_PAD_RIGHT);

			}
		}

		return $blocks;
	}

	/** Преведение 64битного integer к "32битному" на 64битных системах
	 *
	 * @param integer $number
	 */
	private function NormalizeInteger32($number){
		static $is_64bit=null;

		$number=intval($number);

		if(is_null($is_64bit)){
			if(intval(2147483647+1)>0){
				$is_64bit=true;
			}else{
				$is_64bit=false;
			}
		}

		if($is_64bit){
			static $int=null;

			if(is_null($int)){
				$int=0;

				//Генерируем число у которого в двоичном представлении младшие 32 бита - единицы, остальные - нули
				//
				//В 32-битных системах это число "-1"
				//В 64-битных - "4294967295"
				for($i=0; $i<32; $i++){
					$int=$int | (1<<$i);
				}
			}

			//Побитовое AND
			$number=intval($number & $int);
		}

		return $number;
	}
}


