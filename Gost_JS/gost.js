/** Класс осуществляющий работу с шифром ГОСТ 28147-89 (шифрование/дешифрованние данных)
 * @see http://intsystem.org/19/gost-28147-89-php/ (thanks InSys)
 *
 * Переведено на язык javascript 
 * Craager (с) 2014


Пример использования:
<script src="GOST.js" type="text/javascript"></script>

<script>
var gost = new ClassGost(),
	data = "Inner text",
	key = "lkmsdofijw9uri4oikpw934385u4owe2",
	data_encoded = gost.Encode(data, key),
	data_decoded = gost.Decode(data_encoded, key);
</script>


 * 
 */

function ClassGost() {
	/** Количесто иттераций основного шага криптообразования
	 */
	var CNT_MAIN_STEP = 32;

	/** Таблица замен
	 *
	 * @var array
	 */
	var s_block = [
		[6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2],
		[14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9],
		[13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12],
		[7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3],
		[1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12],
		[4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3],
		[4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14],
		[5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11]
	];

	/** Ключ
	 *
	 * @var array
	 */
	var k_block = [
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000,
		0x00000000
	];


	/** Зашифровать данные
	 *
	 * @param string $data данные для шифрования
	 * @param mixed $key ключ шифрования
	 * @param array $table таблица замен
	 * @return mixed возвращает зашифрованную строку, или false в случае неудачи
	 */
	this.Encode = function(data, key, table){
		// utf8 encode
		data = unescape(encodeURIComponent(data));
		if(key){
			if(!this.SetKey(key)){
				return false;
			}
		}

		if(table){
			if(!this.SetTableReplace(table)){
				return false;
			}
		}

		var blocks = LoadData2Blocks(data),
			keys = LoadKeysArray(CNT_MAIN_STEP),
			result='';

		for(var k in blocks){
			result += this.Global_MainStep(blocks[k], keys);
		}

		return result;
	}

	/** Расшифровать данные
	 *
	 * @param string $data зашифрованные данные
	 * @param mixed $key ключ шифрования
	 * @param array $table таблица замен
	 * @return mixed возвращает исходные данные, или false в случае неудачи
	 */
	this.Decode = function(data, key, table){
		if(key){
			if(!this.SetKey(key)){
				return false;
			}
		}

		if(table){
			if(!this.SetTableReplace(table)){
				return false;
			}
		}

		var blocks = LoadData2Blocks(data),
			keys = LoadKeysArray(CNT_MAIN_STEP).reverse(),
			result='';

		for(var k in blocks){
			result += this.Global_MainStep(blocks[k], keys);
		}

		// utf8 decode
		result = decodeURIComponent(escape(result));
		return result;
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
	this.SetKey = function(key){
		if(typeof key == 'string'){
			if(key.length !== 32){
				console.error('SetKey(): "key" length must be equal to 256 bits (32 bytes)');
				return false;
			}

			var new_key = [];

			for(var i = 0; i < 32; i += 4){
				//$tmp=(int)hexdec(bin2hex(substr($key, ($i*4), 4)));

				var tmp = parseInt(bin2hex(key.substr(i, 4)), 16);

				new_key.push(tmp);
			}

			k_block = new_key;
			return true;
		} else if (Array.isArray(key)){
			if(key.length != 8){
				console.error('SetKey(): count of elements in the array "key" must be equal to 8');
				return false;
			}
			
			var new_key = [];

			for(var k in key){
				var val = key[k];

				if(val % 1 != 0){
					console.error('SetKey(): every element of the array "key" must be integer. The array element "table['+k+']" is not an integer.');
					return false;
				}

				new_key.push(val);
			}

			k_block = new_key;
			return true;
		} else {
			console.error('SetKey(): unknown "key" format. "key" must be array[8] of integer or 32-bytes string.');
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
	this.SetTableReplace = function(table){
		if(!Array.isArray(table)){
			console.error('SetTableReplace(): "table" must be array');
			return false;
		}

		if(table.length != 8){
			console.error('SetTableReplace(): count of elements in the array "$table" must be equal to 8');
			return false;
		}

		var i = 0,
			new_array = [];
		
		for(var k in table){
			var val = table[k];

			if(!Array.isArray(val)){
				console.error('SetTableReplace(): table['+k+'] must be array');
				return false;
			}

			if(val.length != 16){
				console.error('SetTableReplace(): count of elements in the array "$table['+k+']" must be equal to 16');
				return false;
			}


			var new_val = [];

			for(var int_key in val){
				var int_val = val[int_key];

				if(int_val % 1 != 0){
					console.error('SetTableReplace(): every element of the array "$table['+k+']" must be integer. The array element "$table['+k+']['+int_key+']" is not an integer.');
					return false;
				}

				if(int_val > 15 || int_val < 0){
					console.error('SetTableReplace(): every element of the array "$table['+k+']" must be greater than or equal to 0 and less than or equal to 15. The array element "$table['+k+']['+int_key+']" is not in this range.');
					return false;
				}
				new_val.push(int_val);
			}

			new_array[i] = new_val;
			i++;
		}


		s_block = new_array;
		return true;
	}

	/** Основной шаг шифрообразования
	 *
	 * @param string $block шифруемый блок
	 * @param array $keys подготовленный массив с ключами
	 * @param intger $cnt_repeat [опционально] количество преобразований
	 * @return string
	 */
	this.Global_MainStep = function(block, keys){
		var cnt_repeat = CNT_MAIN_STEP,
			blockExp = this.Global_BlockExplode(block),
			n1 = blockExp.left,
			n2 = blockExp.right;

		if(keys.length < cnt_repeat){
			cnt_repeat = keys.length;
		}

		for(var i = 0; i < cnt_repeat; i++){
			var val = this.Global_SummMod32(n1, keys[i]);

			val = this.Global_BlockReplace(val);

			val = this.Global_BlockCycleShift(val, 21);

			val = val ^ n2;

			n2 = n1;
			n1 = val;
		}


		block = this.Global_BlockImplode(n2, n1);
		return block;
	}

	/** Функция цикличного побитового сдвига вправо
	 *
	 * @param integer $block
	 * @param integer $bits количество битов для сдвига
	 * @return integer
	 */
	this.Global_BlockCycleShift = function(block, bits){
		if(bits > 0){
			var a = bits,
				b = 32 - a;
			
			block = ((block >> a) & ~(-Math.pow(2,b)))^(block << b);
		}
		return block;
	}

	/** Замена по таблице замен
	 *
	 * @param integer $block текущий блок для замены
	 * @return integer
	 */
	this.Global_BlockReplace = function(block){
		var new_block = 0;

		for(var i = 0; i < 8; i++){
			//Вычленяем нужные 4 бита под замену
			var rem = block>>(4*(i+1)),
				hex;
			rem = rem<<(4*(i+1));

			if(i == 7){
				hex = rem;
			}else{
				hex = block - rem;
				block = rem;
			}

			hex = this.Global_BlockCycleShift(hex,(4*i));

			//Находим на какое число его заменять по таблице замен
			var replace = s_block[i][hex];

			//Заменяем
			new_block = new_block + (Math.pow(16, i)*replace);
		}

		return new_block;
	}

	/** Суммирование двух чисел по модулю 32
	 *
	 * @param integer $bin1 число (4 байта)
	 * @param integer $bin2 число (4 байта)
	 * @return integer результат вычисления (4 байта)
	 */
	this.Global_SummMod32 = function(bin1, bin2){
		return NormalizeInteger32(parseInt(bin1 + bin2));
	}

	/** Разбиение блока на "правую" и "левую" часть
	 *
	 * @param string $block входной блок (8 байт)
	 * @param &integer $left левая часть (накопитель N1) (4 байта)
	 * @param &integer $right правая часть (накопитель N2) (4 байта)
	 */
	this.Global_BlockExplode = function(block){
		var left = '',
			right = '';

		left = block.substr(0, 4);
		right = block.substr(4, 4);
		

		return {
			left: parseInt(bin2hex(left), 16),
			right: parseInt(bin2hex(right), 16)
		};
	}

	/** Разбиение блока на "правую" и "левую" часть
	 *
	 * @param &string $block входной блок (8 байт)
	 * @param integer $left левая часть (накопитель N1) (4 байта)
	 * @param integer $right правая часть (накопитель N2) (4 байта)
	 */
	this.Global_BlockImplode = function(left, right){
		var block = '';

		left = sprintf("%08x", left);
		right = sprintf("%08x", right);

		var arr = left.match(RegExp("((.{2})+?|(.{1,2})$)", "g"));
		
		for(var k in arr){
			block += String.fromCharCode(parseInt(arr[k], 16));
		}


		arr = right.match(RegExp("((.{2})+?|(.{1,2})$)", "g"));
		for(var k in arr){
			block += String.fromCharCode(parseInt(arr[k], 16));
		}

		return block;
	}

	/** Генерируем массив с ключами
	 *
	 * @param integer $cnt_repeat количество ключей
	 * @return array
	 */
	LoadKeysArray = function(cnt_repeat){
		if(!cnt_repeat) {
			cnt_repeat = CNT_MAIN_STEP;
		}

		var key_block = [];
		for(var i = 0; i < cnt_repeat; i++){
			var x;
			if(i < (cnt_repeat - 8)){
				x = i % 8;
			}else{
				x = 7 - (i % 8);
			}
			
			key_block.push(k_block[x]);
		}

		return key_block;
	}

	/** Разбиваем данные на блоки по 64 бита (8 байт)
	 *
	 * @param string $data входные данные
	 * @param integer $block_size [опционально] (64 - дефолт) размерность блоков
	 * @return array выходной массив с блоками
	 */
	LoadData2Blocks = function(data){
		var block_size = 64,
			blocks = [],
			block_len = parseInt(block_size / 8);

		for(var i = 0, x = (Math.ceil(data.length/block_len)); i < x; i++){
			blocks[i] = data.substr(i * block_len, block_len);

			if(i == (x - 1)){
				//Если последний блок не полон, то дополняем его нулями
				while (blocks[i].length < block_len){
					blocks[i] += String.fromCharCode(0);
				}
			}
		}

		return blocks;
	}

	/** Преведение 64битного integer к "32битному" на 64битных системах
	 *
	 * @param integer $number
	 */
	NormalizeInteger32 = function(number){
		var is_64bit = null;

		number = parseInt(number);

		if(is_64bit === null){
			if(parseInt(2147483647+1) > 0){
				is_64bit = true;
			} else {
				is_64bit=false;
			}
		}

		if(is_64bit){
			var integer = null;

			if(integer === null){
				integer = 0;

				//Генерируем число у которого в двоичном представлении младшие 32 бита - единицы, остальные - нули
				//
				//В 32-битных системах это число "-1"
				//В 64-битных - "4294967295"
				for(var i = 0; i < 32; i++){
					integer = integer | (1 << i);
				}
			}

			//Побитовое AND
			number = parseInt(number & integer);
		}

		return number;
	}
}


/* АНАЛОГИ PHP ФУНКЦИЙ */
function bin2hex(s) {
  //  discuss at: http://phpjs.org/functions/bin2hex/
  // original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // bugfixed by: Onno Marsman
  // bugfixed by: Linuxworld
  // improved by: ntoniazzi (http://phpjs.org/functions/bin2hex:361#comment_177616)
  //   example 1: bin2hex('Kev');
  //   returns 1: '4b6576'
  //   example 2: bin2hex(String.fromCharCode(0x00));
  //   returns 2: '00'

  var i, l, o = '', n;

  s += '';

  for (i = 0, l = s.length; i < l; i++) {
    n = s.charCodeAt(i).toString(16);
    o += n.length < 2 ? '0' + n : n;
  }

  return o;
}

function sprintf() {
  //  discuss at: http://phpjs.org/functions/sprintf/
  // original by: Ash Searle (http://hexmen.com/blog/)
  // improved by: Michael White (http://getsprink.com)
  // improved by: Jack
  // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
  // improved by: Dj
  // improved by: Allidylls
  //    input by: Paulo Freitas
  //    input by: Brett Zamir (http://brett-zamir.me)
  //   example 1: sprintf("%01.2f", 123.1);
  //   returns 1: 123.10
  //   example 2: sprintf("[%10s]", 'monkey');
  //   returns 2: '[    monkey]'
  //   example 3: sprintf("[%'#10s]", 'monkey');
  //   returns 3: '[####monkey]'
  //   example 4: sprintf("%d", 123456789012345);
  //   returns 4: '123456789012345'
  //   example 5: sprintf('%-03s', 'E');
  //   returns 5: 'E00'

  var regex = /%%|%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuideEfFgG])/g;
  var a = arguments;
  var i = 0;
  var format = a[i++];

  // pad()
  var pad = function(str, len, chr, leftJustify) {
    if (!chr) {
      chr = ' ';
    }
    var padding = (str.length >= len) ? '' : new Array(1 + len - str.length >>> 0)
      .join(chr);
    return leftJustify ? str + padding : padding + str;
  };

  // justify()
  var justify = function(value, prefix, leftJustify, minWidth, zeroPad, customPadChar) {
    var diff = minWidth - value.length;
    if (diff > 0) {
      if (leftJustify || !zeroPad) {
        value = pad(value, minWidth, customPadChar, leftJustify);
      } else {
        value = value.slice(0, prefix.length) + pad('', diff, '0', true) + value.slice(prefix.length);
      }
    }
    return value;
  };

  // formatBaseX()
  var formatBaseX = function(value, base, prefix, leftJustify, minWidth, precision, zeroPad) {
    // Note: casts negative numbers to positive ones
    var number = value >>> 0;
    prefix = prefix && number && {
      '2': '0b',
      '8': '0',
      '16': '0x'
    }[base] || '';
    value = prefix + pad(number.toString(base), precision || 0, '0', false);
    return justify(value, prefix, leftJustify, minWidth, zeroPad);
  };

  // formatString()
  var formatString = function(value, leftJustify, minWidth, precision, zeroPad, customPadChar) {
    if (precision != null) {
      value = value.slice(0, precision);
    }
    return justify(value, '', leftJustify, minWidth, zeroPad, customPadChar);
  };

  // doFormat()
  var doFormat = function(substring, valueIndex, flags, minWidth, _, precision, type) {
    var number, prefix, method, textTransform, value;

    if (substring === '%%') {
      return '%';
    }

    // parse flags
    var leftJustify = false;
    var positivePrefix = '';
    var zeroPad = false;
    var prefixBaseX = false;
    var customPadChar = ' ';
    var flagsl = flags.length;
    for (var j = 0; flags && j < flagsl; j++) {
      switch (flags.charAt(j)) {
        case ' ':
          positivePrefix = ' ';
          break;
        case '+':
          positivePrefix = '+';
          break;
        case '-':
          leftJustify = true;
          break;
        case "'":
          customPadChar = flags.charAt(j + 1);
          break;
        case '0':
          zeroPad = true;
          customPadChar = '0';
          break;
        case '#':
          prefixBaseX = true;
          break;
      }
    }

    // parameters may be null, undefined, empty-string or real valued
    // we want to ignore null, undefined and empty-string values
    if (!minWidth) {
      minWidth = 0;
    } else if (minWidth === '*') {
      minWidth = +a[i++];
    } else if (minWidth.charAt(0) == '*') {
      minWidth = +a[minWidth.slice(1, -1)];
    } else {
      minWidth = +minWidth;
    }

    // Note: undocumented perl feature:
    if (minWidth < 0) {
      minWidth = -minWidth;
      leftJustify = true;
    }

    if (!isFinite(minWidth)) {
      throw new Error('sprintf: (minimum-)width must be finite');
    }

    if (!precision) {
      precision = 'fFeE'.indexOf(type) > -1 ? 6 : (type === 'd') ? 0 : undefined;
    } else if (precision === '*') {
      precision = +a[i++];
    } else if (precision.charAt(0) == '*') {
      precision = +a[precision.slice(1, -1)];
    } else {
      precision = +precision;
    }

    // grab value using valueIndex if required?
    value = valueIndex ? a[valueIndex.slice(0, -1)] : a[i++];

    switch (type) {
      case 's':
        return formatString(String(value), leftJustify, minWidth, precision, zeroPad, customPadChar);
      case 'c':
        return formatString(String.fromCharCode(+value), leftJustify, minWidth, precision, zeroPad);
      case 'b':
        return formatBaseX(value, 2, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
      case 'o':
        return formatBaseX(value, 8, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
      case 'x':
        return formatBaseX(value, 16, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
      case 'X':
        return formatBaseX(value, 16, prefixBaseX, leftJustify, minWidth, precision, zeroPad)
          .toUpperCase();
      case 'u':
        return formatBaseX(value, 10, prefixBaseX, leftJustify, minWidth, precision, zeroPad);
      case 'i':
      case 'd':
        number = +value || 0;
        number = Math.round(number - number % 1); // Plain Math.round doesn't just truncate
        prefix = number < 0 ? '-' : positivePrefix;
        value = prefix + pad(String(Math.abs(number)), precision, '0', false);
        return justify(value, prefix, leftJustify, minWidth, zeroPad);
      case 'e':
      case 'E':
      case 'f': // Should handle locales (as per setlocale)
      case 'F':
      case 'g':
      case 'G':
        number = +value;
        prefix = number < 0 ? '-' : positivePrefix;
        method = ['toExponential', 'toFixed', 'toPrecision']['efg'.indexOf(type.toLowerCase())];
        textTransform = ['toString', 'toUpperCase']['eEfFgG'.indexOf(type) % 2];
        value = prefix + Math.abs(number)[method](precision);
        return justify(value, prefix, leftJustify, minWidth, zeroPad)[textTransform]();
      default:
        return substring;
    }
  };

  return format.replace(regex, doFormat);
}
