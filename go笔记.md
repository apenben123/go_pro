

## golang 遇到问题

### 1. go import 本地包 

有如下目录结构

```
src
├─── go.mod
├─── test.go
└─┬─ accesstoken
  ├─── accesstoken.go
  └─── accesstoken_test.go
```

go.mod 中定义模块名， 如：module test 即为 test 模块，**每个module有一个go.mod文件**

```mod
module test
go 1.17
```

accesstoken.go 中定义 package 包名

```go
package accesstoken

func getAccountTokenInfo (accessToken string) (int, TOKEN_INFO) {

}
```

test.go 中 import 本地包 "module/package"，**一个module可以有多个package**

```go
package main

import (
	"fmt"
	"test/accesstoken"
)

func main() {
	ret, stToken := accesstoken.GetAccountTokenInfo("TOKEN1000084ID111111")
	fmt.Println(ret)
	fmt.Printf("token=%+v\n", stToken)
}
```



**不在同一个父项目下的 import**

目录结构如下

```
src
├─┬─ main
│ ├─── test.go
│ └─── go.mod
└─┬─ accesstoken
  ├─── accesstoken.go
  ├─── accesstoken_test.go
  └─── go.mod
```

此时需要对 accesstoken 目录也进行模块化，即有自己的 go.mod 文件

```
module accesstoken
go 1.17
```

然后在调用的包中进行导入

由于2个包不在同一项目路径下，所以需要使用 replace 指令来指定使用相对路径来寻找 accesstoken 这个包，import 包必须带上版本名，版本名格式为**“v+三个点分隔的非负整数”**.（测试发现：本地包版本号可以随意填）

```
module test
go 1.17

require "accesstoken" v1.0.0
replace	"accesstoken" => "../accesstoken"
```

然后在test.go中进行导入

```go
package main

import (
	"accesstoken"
	"fmt"
)

func main() {
	ret, stToken := accesstoken.GetAccountTokenInfo("TOKEN1000084ID111111")
	fmt.Println(ret)
	fmt.Printf("token=%+v\n", stToken)
}

```



### 2. 使用了未导出的函数 'getAccountTokenInfo' 

在 Go package 中，当***变量或函数的首字母大写***的时候，**函数会被从包中导出（在包外部可见，或者说公有的**）

getAccountTokenInfo 改为 GetAccountTokenInfo 即可

>公有函数的名字以大写字母开头；
>
>私有函数的名字以小写字母开头。



### 3. go 安装 thrift v0.10.0

thrift采用go/src目录下go安装

注: git直接下载下来为master版本，请*带上版本号*

```shell
$ go get git.apache.org/thrift.git/lib/go/thrift@0.10.0
```

由于 git.apache.org/thrift.git/lib/go/thrift 访问不到，所以先设置代理

```shell
$ go env -w GO111MODULE=on
$ go env -w GOPROXY=https://goproxy.cn,direct
```

### 4.  go + thrift 注意事项

1. thrift 中 optional 字段在 go 中使用指针传递，request param 中的 optional 字段需要指向实际的地址（变量）。

2. thrift 中 typedef 在 golang 中对应为 type。但是 go 语言 type 的特殊性导致赋值可能存在问题。需要进行调整

   ```go
   package main
   
   import (
   	"fmt"
   	"reflect"
   )
   
   type UID = int64
   type USER_ID int64  //USER_ID 类型与 int64 拥有相同的特性，但两者是不同的类型
   
   func main() {
   	var iuser int64 = 50000001
   	var uuser UID = 50000001
   	var suser USER_ID = 50000001
   	fmt.Println("iuser:", reflect.TypeOf(iuser)) //iuser: int64
   	fmt.Println("uuser:", reflect.TypeOf(uuser)) //uuser: int64   
   	fmt.Println("suser:", reflect.TypeOf(suser)) //suser: main.USER_ID
   	uuser = iuser
   	suser = iuser //提示错误：无法将 'iuser' (类型 int64) 用作类型 USER_ID
   }
   ```

   >`type NewType ExistingType` **Named Types** 就是通过 type 关键字为一个已有的 type 起个别名。NewType  类型与 ExistingType 拥有相同的特性，但两者是不同的类型。
   >
   >**为什么 type 之间会有这样的差别?**
   >
   >如果为一个类型起了名字，说明你想要做区分，所以两个 named types 是不能相互赋值的。
   >
   >type详细说明：https://sanyuesha.com/2017/07/27/go-type/
   >
   >**=** 是赋值运算符，不是起别名

3. server 和 client 之间需要保证 Protocol 与 Transport 是相同匹配的 

   > 协议 Protocol
   >
   > *TBinaryProtocol*		  ：二进制编码格式进行数据传输
   > *TCompactProtocol*	  ：高效率的、密集的二进制编码格式进行数据传输
   > *TJSONProtocol*			 ：使用 JSON 的数据编码协议进行数据传输
   > *TSimpleJSONProtocol*  ：只提供 JSON 只写的协议，适用于通过脚本语言解析
   >
   > 传输层  Transport
   > *TSocket*						    ：使用阻塞式 I/O 进行传输，是最常见的模式
   > *TFramedTransport*	     ：使用非阻塞方式，按块的大小进行传输。若使用 TFramedTransport 传输层，其服务器必须修改为非阻塞的服务类型。
   > *TNonblockingTransport* ：使用非阻塞方式，用于构建异步客户端
   >
   > 服务器端类型
   > *TSimpleServer*			   ：单线程服务器端使用标准的阻塞式 I/O
   > *TThreadPoolServer*	   ：多线程服务器端使用标准的阻塞式 I/O
   > *TNonblockingServer*	 ：多线程服务器端使用非阻塞式 I/O

   homed c++ 服务均为 ***TBinaryProtocol + TFramedTransport + TNonblockingServer***



### 5. go调用c++

[cgo类型转换 ](https://blog.csdn.net/weixin_36771703/article/details/89003014)

[cgo类型](https://blog.csdn.net/darlingtangli/article/details/84198859)

[cgo内存泄漏](https://ask.csdn.net/questions/1020754)

[go调用c++](https://www.codercto.com/a/39274.html)

**go 不支持直接调用c++，需要用c做转接。**

目录结构

```shell
[root@master(106.210) /homed/iusm/zhouyu/go/test/src/playtoken]# tree
.
├── cpp
│   ├── stdafx.h			//cpp依赖头文件
│   ├── XtMacros.h			//cpp依赖头文件
│   ├── ext_sec_io.cpp		//cpp文件 基本算法
│   ├── ext_sec_io.h		//cpp文件
│   ├── com_base62.cpp		//cpp文件 基本算法
│   ├── com_base62.h		//cpp文件 
│   ├── com_crc.cpp			//cpp文件 基本算法
│   ├── com_crc.h			//cpp文件
│   ├── com_play_token.cpp	//cpp文件 生成playtoken
│   ├── com_play_token.h	//cpp文件
│   ├── Makefile			//编译生成so
│   ├── play_token.cpp		//c转接文件
│   └── play_token.h		//c转接文件
├── lib
│   └── libplaytoken.so		//so库文件
├── playtoken.go			//go
└── playtoken_test.go
```

 play_token.h:

```c
#ifndef __PLAY_TOKEN_H__
#define __PLAY_TOKEN_H__

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdint.h>
    
char* get_video_play_token_ver1(const char* ip_addr, const char* fileName, uint16_t nTrailTime, int32_t nPlatform);

#ifdef __cplusplus
}
#endif

#endif /* __PLAY_TOKEN_H__ */
```

 play_token.cpp:

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "com_play_token.h"
#include "play_token.h"    //少了这行会报下面2类型的错误

char*  get_video_play_token_ver1(const char* ip_addr, const char* fileName, uint16_t nTrailTime, int32_t nPlatform, int32_t debug=0)
{
        int32_t ret = -1;
        SPlayTokenInfo tokenInfo;
        char* playToken = NULL;

        tokenInfo.nIsOwn                = 1; //! 不鉴权
        tokenInfo.nPlayType     = 3; //! EContentLabel::VOD
        tokenInfo.nStartTime    = 0; //! starttime 固定填 0
        tokenInfo.strIP                 = ip_addr;
        tokenInfo.strFileName   = fileName;
        tokenInfo.nTrailTime    = nTrailTime;
        if (nPlatform!=(PLATFORM_ID)-1)
        {
                tokenInfo.setPlatform.insert(nPlatform);
        }

        string strPlayToken;
        ret = getPlayTokenVer1(tokenInfo, strPlayToken);
        if (!strPlayToken.empty())
        {
                playToken = (char*)malloc(strPlayToken.size() + 1);
                memcpy(playToken, strPlayToken.c_str(), strPlayToken.size());
                playToken[strPlayToken.size() + 1] = 0;
        }

    if (debug == 1)
    {
        printf("strPlayToken=%s\n", strPlayToken.c_str());
        printf("playToken=%s\n", playToken);
    }

        return NULL;
}
```

其他文件就按照c++语法写就行了。转接文件只能是c语法。

且要 extern "C" {} 才能被 cgo 调用。

因为cgo支持的

1. 找不到so库文件

   ```shell
   [root@master(106.210) /homed/iusm/zhouyu/go/test/src]# go run   test.go
   /tmp/go-build462151488/b001/exe/test: error while loading shared libraries: libplaytoken.so: cannot open shared object file: No such file or directory
   exit status 127
   ```

   在 go build 的时候指定so的路径： go build -ldflags="-r ./" test.go

   ```shell
   [root@master(106.210) /homed/iusm/zhouyu/go/test/src]# go run -ldflags="-r ./playtoken/cpp" test.go
   ```

   [go调用so库](https://blog.csdn.net/weixin_38374974/article/details/99842556)

2. 对‘get_video_play_token_ver1’未定义的引用

   ```shell
   /tmp/go-build201443194/b001/_x002.o：在函数‘_cgo_13df3c7e1799_Cfunc_get_video_play_token_ver1’中：
   /tmp/go-build/cgo-gcc-prolog:58：对‘get_video_play_token_ver1’未定义的引用
   ```

   检查 play_token.cpp 文件中是否有 #include "play_token.h" 头文件
