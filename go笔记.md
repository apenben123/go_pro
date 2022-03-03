

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

3.  server 和 client 之间需要保证 Protocol 与 Transport 是相同匹配的 

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

4.  

