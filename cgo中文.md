# 命令 cgo

Cgo 允许创建调用 C 代码的 Go 包。

### 通过 go 命令使用 cgo

要使用 cgo，请编写导入伪包“C”的普通 Go 代码。然后，Go 代码可以引用诸如 C.size_t 之类的类型、诸如 C.stdout 之类的变量或诸如 C.putchar 之类的函数。

如果“C”的导入紧跟在注释之前，则该注释称为前导，在编译包的 C 部分时用作标题。例如：

```go
// #include <stdio.h> 
// #include <errno.h>
import "C"
```

序言可以包含任何 C 代码，包括函数和变量声明和定义。然后可以从 Go 代码中引用它们，就好像它们是在包“C”中定义的一样。可以使用序言中声明的所有名称，即使它们以小写字母开头。例外：前导中的静态变量可能不会被 Go 代码引用；允许使用静态函数。

有关示例，请参见 $GOROOT/misc/cgo/stdio 和 $GOROOT/misc/cgo/gmp。见“C？Go？Cgo！” 使用 cgo 的介绍： [https](https://golang.org/doc/articles/c_go_cgo.html) ://golang.org/doc/articles/c_go_cgo.html 。

CFLAGS、CPPFLAGS、CXXFLAGS、FFLAGS 和 LDFLAGS 可以在这些注释中使用伪 #cgo 指令定义，以调整 C、C++ 或 Fortran 编译器的行为。多个指令中定义的值连接在一起。该指令可以包含一个构建约束列表，将其影响限制为满足其中一个约束的系统（有关约束语法的详细信息，请参见https://golang.org/pkg/go/build/#hdr-Build_Constraints）。例如：

```go
// #cgo CFLAGS: -DPNG_DEBUG=1 
// #cgo amd64 386 CFLAGS: -DX86=1 
// #cgo LDFLAGS: -lpng 
// #include <png.h> 
import "C"
```

或者，CPPFLAGS 和 LDFLAGS 可以通过 pkg-config 工具使用 '#cgo pkg-config:' 指令后跟包名称来获得。例如：

```go
// #cgo pkg-config: png cairo 
// #include <png.h> 
import "C"
```

可以通过设置 PKG_CONFIG 环境变量来更改默认的 pkg-config 工具。

出于安全原因，只允许使用一组有限的标志，特别是 -D、-U、-I 和 -l。要允许附加标志，请将 CGO_CFLAGS_ALLOW 设置为匹配新标志的正则表达式。要禁止原本允许的标志，请将 CGO_CFLAGS_DISALLOW 设置为匹配必须禁止的参数的正则表达式。在这两种情况下，正则表达式都必须匹配一个完整的参数：要允许 -mfoo=bar，请使用 CGO_CFLAGS_ALLOW='-mfoo.*'，而不仅仅是 CGO_CFLAGS_ALLOW='-mfoo'。类似命名的变量控制允许的 CPPFLAGS、CXXFLAGS、FFLAGS 和 LDFLAGS。

同样出于安全原因，只允许使用有限的字符集，尤其是字母数字字符和一些符号，例如“.”，它们不会以意想不到的方式解释。尝试使用禁止字符将得到“格式错误的 #cgo 参数”错误。

构建时，将 CGO_CFLAGS、CGO_CPPFLAGS、CGO_CXXFLAGS、CGO_FFLAGS 和 CGO_LDFLAGS 环境变量添加到从这些指令派生的标志中。应使用指令设置特定于包的标志，而不是环境变量，以便构建在未修改的环境中工作。从环境变量获得的标志不受上述安全限制的约束。

包中的所有 cgo CPPFLAGS 和 CFLAGS 指令都被连接起来，用于编译该包中的 C 文件。包中的所有 CPPFLAGS 和 CXXFLAGS 指令都被连接起来并用于编译该包中的 C++ 文件。包中的所有 CPPFLAGS 和 FFLAGS 指令都被连接起来并用于编译该包中的 Fortran 文件。程序中任何包中的所有 LDFLAGS 指令都被连接起来并在链接时使用。所有 pkg-config 指令都被连接起来并同时发送到 pkg-config 以添加到每个适当的命令行标志集。

解析 cgo 指令时，任何出现的字符串 ${SRCDIR} 都将替换为包含源文件的目录的绝对路径。这允许将预编译的静态库包含在包目录中并正确链接。例如，如果包 foo 在目录 /go/src/foo 中：

```go
// #cgo LDFLAGS: -L${SRCDIR}/libs -lfoo
```

将扩展为：

```go
// #cgo LDFLAGS: -L/go/src/foo/libs -lfoo
```

当 Go 工具看到一个或多个 Go 文件使用了特殊的 import "C" 时，它会在目录中查找其他非 Go 文件并将它们编译为 Go 包的一部分。任何 .c、.s、.S 或 .sx 文件都将使用 C 编译器进行编译。任何 .cc、.cpp 或 .cxx 文件都将使用 C++ 编译器进行编译。任何 .f、.F、.for 或 .f90 文件都将使用 fortran 编译器进行编译。任何 .h、.hh、.hpp 或 .hxx 文件都不会被单独编译，但是，如果这些头文件被更改，包（包括其非 Go 源文件）将被重新编译。请注意，更改其他目录中的文件不会导致重新编译包，因此包的所有非 Go 源代码都应存储在包目录中，而不是子目录中。默认的 C 和 C++ 编译器可能会被 CC 和 CXX 环境变量更改，分别; 这些环境变量可能包括命令行选项。

cgo 工具将始终使用包含路径中的源文件目录调用 C 编译器；即 -I${SRCDIR} 总是隐含的。这意味着如果头文件 foo/bar.h 存在于源目录和系统包含目录（或由 -I 标志指定的其他位置）中，则 "#include <foo/bar.h>"总是会优先于任何其他版本找到本地版本。

默认情况下，cgo 工具在预期可以工作的系统上为本地构建启用。交叉编译时默认禁用。您可以通过在运行 go 工具时设置 CGO_ENABLED 环境变量来控制这一点：将其设置为 1 以启用 cgo 的使用，设置为 0 以禁用它。如果启用了 cgo，go 工具将设置构建约束“cgo”。特殊的导入“C”暗示了“cgo”构建约束，就好像文件也说“// +build cgo”一样。因此，如果禁用 cgo，则 go 工具将不会构建导入“C”的文件。（有关构建约束的更多信息，请参见https://golang.org/pkg/go/build/#hdr-Build_Constraints）。

交叉编译时，必须指定 C 交叉编译器供 cgo 使用。在使用 make.bash 构建工具链时，您可以通过设置通用 CC_FOR_TARGET 或更具体的 CC_FOR_${GOOS}_${GOARCH}（例如 CC_FOR_linux_arm）环境变量来完成此操作，或者您可以随时设置 CC 环境变量你运行 go 工具。

CXX_FOR_TARGET、CXX_FOR_${GOOS}_${GOARCH} 和 CXX 环境变量的工作方式与 C++ 代码类似。

### 转到 C 的引用

在 Go 文件中，作为 Go 中关键字的 C 结构字段名称可以通过以下划线作为前缀来访问：如果 x 指向具有名为“type”的字段的 C 结构，则 x._type 访问该字段。在 Go 结构中无法表达的 C 结构字段，例如位字段或未对齐的数据，在 Go 结构中被省略，替换为适当的填充以到达下一个字段或结构的末尾。

标准 C 数字类型的名称有 C.char、C.schar（有符号字符）、C.uchar（无符号字符）、C.short、C.ushort（无符号短）、C.int、C.uint（ unsigned int), C.long, C.ulong (unsigned long), C.longlong (long long), C.ulonglong (unsigned long long), C.float, C.double, C.complexfloat (复数浮点), 和C.complexdouble（复数双）。C 类型 void* 由 Go 的 unsafe.Pointer 表示。C 类型 __int128_t 和 __uint128_t 由 [16]byte 表示。

一些在 Go 中通常由指针类型表示的特殊 C 类型改为由 uintptr 表示。请参阅下面的特殊情况部分。

要直接访问 struct、union 或 enum 类型，请在其前面加上 struct_、union_ 或 enum_，如 C.struct_stat 中所示。

任何 C 类型 T 的大小都可以作为 C.sizeof_T 使用，如在 C.sizeof_struct_stat 中。

一个C 函数可以在 Go 文件中以特殊名称 _GoString_ 的参数类型声明。可以使用普通的 Go 字符串值调用此函数。可以通过调用 C 函数来访问字符串长度和指向字符串内容的指针

```c
size_t _GoStringLen(_GoString_s); 
const char *_GoStringPtr(_GoString_s);
```

这些函数仅在序言中可用，在其他 C 文件中不可用。C 代码不得修改 _GoStringPtr 返回的指针的内容。请注意，字符串内容可能没有尾随 NUL 字节。

由于 Go 在一般情况下不支持 C 的联合类型，因此 C 的联合类型表示为具有相同长度的 Go 字节数组。

Go 结构不能嵌入具有 C 类型的字段。

Go 代码不能引用出现在非空 C 结构末尾的零大小字段。要获取此类字段的地址（这是您可以对零大小字段执行的唯一操作），您必须获取结构的地址并添加结构的大小。

Cgo 将 C 类型转换为等效的未导出 Go 类型。因为翻译是未导出的，所以 Go 包不应该在其导出的 API 中暴露 C 类型：一个 Go 包中使用的 C 类型与另一个包中使用的相同 C 类型不同。

可以在多重赋值上下文中调用任何 C 函数（甚至是 void 函数）来检索返回值（如果有）和 C errno 变量作为错误（如果函数返回 void，则使用 _ 跳过结果值）。例如：

```go
n, err = C.sqrt(-1) 
_, err := C.voidFunc() 
var n, err = C.sqrt(1)
```

目前不支持调用 C 函数指针，但是您可以声明保存 C 函数指针并在 Go 和 C 之间来回传递它们的 Go 变量。C 代码可能会调用从 Go 接收的函数指针。例如：

```go
package main 

// typedef int (*intFunc) (); 
// 
// int 
// bridge_int_func(intFunc f) 
// { 
// return f(); 
// } 
// 
// int fortytwo() 
// { 
// return 42; 
// } 
import "C" 
import "fmt" 

func main() { 
	f := C.intFunc(C.fortytwo) 
	fmt.Println(int(C.bridge_int_func(f))) 
	// 输出：42 
}
```

在 C 中，编写为固定大小数组的函数参数实际上需要指向数组第一个元素的指针。C 编译器知道这种调用约定并相应地调整调用，但 Go 不能。在 Go 中，您必须将指针显式传递给第一个元素：Cf(&C.x[0])。

不支持调用可变 C 函数。可以通过使用 C 函数包装器来规避这一点。例如：

```go
package main 

// #include <stdio.h> 
// #include <stdlib.h> 
// 
// static void myprint(char* s) { 
// printf("%s\n", s); 
// } 
import "C" 
import "unsafe" 

func main() { 
	cs := C.CString("Hello from stdio") 
	C.myprint(cs) 
	C.free(unsafe.Pointer(cs)) 
}
```

一些特殊函数通过复制数据在 Go 和 C 类型之间进行转换。在伪 Go 定义中：

```go
// Go string to C string 
// C 字符串使用 malloc 在 C 堆中分配。
// 调用者有责任安排它被释放 
// 例如通过调用 C.free（如果需要 C.free，请确保包含 stdlib.h //）。
func C.CString(string) *C.char 

// Go []byte slice to C array 
// C 数组使用 malloc 在 C 堆中分配。
// 调用者有责任安排它被释放 
// 例如通过调用 C.free（如果需要 C.free，请确保包含 stdlib.h //）。
func C.CBytes([]byte) unsafe.Pointer 

// C 字符串到 Go 字符串
func C.GoString(*C.char) string 

// 具有显式长度的 C 数据到 Go 字符串
func C.GoStringN(*C.char, C.int) string 

// 具有显式长度的 C 数据到 Go []byte 
func C.GoBytes(unsafe.Pointer, C.int) []byte
```

作为一种特殊情况，C.malloc 不直接调用 C 库 malloc，而是调用一个包装 C 库 malloc 但保证永远不会返回 nil 的 Go 辅助函数。如果 C 的 malloc 指示内存不足，则辅助函数会使程序崩溃，就像 Go 本身内存不足时一样。因为 C.malloc 不能失败，所以它没有返回 errno 的双结果形式。

### C 对 Go 的引用

Go 函数可以通过以下方式导出以供 C 代码使用：

```go
//export MyFunction 
func MyFunction(arg1, arg2 int, arg3 string) int64 {...} 

//export MyFunction2 
func MyFunction2(arg1, arg2 int, arg3 string) (int64, *C.char) {...}
```

它们将在 C 代码中提供为：

```c
extern GoInt64 MyFunction(int arg1, int arg2, GoString arg3); 
extern struct MyFunction2_return MyFunction2(int arg1, int arg2, GoString arg3);
```

在 _cgo_export.h 生成的标头中找到，位于从 cgo 输入文件复制的任何前导码之后。具有多个返回值的函数被映射到返回结构的函数。

并非所有 Go 类型都可以以有用的方式映射到 C 类型。不支持 Go 结构类型；使用 C 结构类型。不支持 Go 数组类型；使用 C 指针。

接受字符串类型参数的 Go 函数可以使用 C 类型 _GoString_ 调用，如上所述。_GoString_ 类型将在序言中自动定义。请注意，C 代码无法创建这种类型的值；这仅适用于将字符串值从 Go 传递到 C 并返回到 Go。

在文件中使用 //export 对前导有一个限制：因为它被复制到两个不同的 C 输出文件中，所以它不能包含任何定义，只能包含声明。如果一个文件同时包含定义和声明，那么这两个输出文件将产生重复的符号并且链接器将失败。为避免这种情况，定义必须放在其他文件或 C 源文件的前导中。

### 传递指针

Go 是一种垃圾收集语言，垃圾收集器需要知道每个指向 Go 内存的指针的位置。因此，在 Go 和 C 之间传递指针是有限制的。

在本节中，术语 Go 指针表示指向由 Go 分配的内存的指针（例如通过使用 & 运算符或调用预定义的新函数），术语 C 指针表示指向由 C 分配的内存的指针（例如通过调用C.malloc)。指针是 Go 指针还是 C 指针是由内存分配方式决定的动态属性；它与指针的类型无关。

请注意，除了类型的零值之外，某些 Go 类型的值始终包含 Go 指针。这适用于字符串、切片、接口、通道、映射和函数类型。指针类型可以保存 Go 指针或 C 指针。数组和结构类型可能包含也可能不包含 Go 指针，具体取决于元素类型。下面所有关于 Go 指针的讨论不仅适用于指针类型，还适用于包括 Go 指针的其他类型。

Go 代码可以将 Go 指针传递给 C，前提是它指向的 Go 内存不包含任何 Go 指针。C 代码必须保留这个属性：它不能在 Go 内存中存储任何 Go 指针，即使是暂时的。当传递一个指向结构体中字段的指针时，所讨论的 Go 内存是该字段占用的内存，而不是整个结构体。当传递指向数组或切片中元素的指针时，所讨论的 Go 内存是切片的整个数组或整个后备数组。

调用返回后，C 代码可能不会保留 Go 指针的副本。这包括 _GoString_ 类型，如上所述，它包括一个 Go 指针；_GoString_ 值可能不会被 C 代码保留。

C 代码调用的 Go 函数可能不会返回 Go 指针（这意味着它可能不会返回字符串、切片、通道等）。C 代码调用的 Go 函数可以将 C 指针作为参数，它可以通过这些指针存储非指针或 C 指针数据，但它可能不会在 C 指针指向的内存中存储 Go 指针。C 代码调用的 Go 函数可以将 Go 指针作为参数，但它必须保留其指向的 Go 内存不包含任何 Go 指针的属性。

Go 代码可能不会在 C 内存中存储 Go 指针。C 代码可以将 Go 指针存储在 C 内存中，但须遵守上述规则：当 C 函数返回时，它必须停止存储 Go 指针。

这些规则在运行时动态检查。检查由 GODEBUG 环境变量的 cgocheck 设置控制。默认设置是 GODEBUG=cgocheck=1，它实现了相当便宜的动态检查。可以使用 GODEBUG=cgocheck=0 完全禁用这些检查。通过 GODEBUG=cgocheck=2 可以在运行时完成对指针处理的检查，但需要付出一定的代价。

可以通过使用 unsafe 包来克服这种强制，当然没有什么可以阻止 C 代码做任何它喜欢的事情。但是，违反这些规则的程序很可能会以意想不到和不可预知的方式失败。

runtime/cgo.Handle 类型可用于在 Go 和 C 之间安全地传递 Go 值。有关详细信息，请参阅 runtime/cgo 包文档。

注意：当前的实现有一个错误。虽然允许 Go 代码将 nil 或 C 指针（但不是 Go 指针）写入 C 内存，但如果 C 内存的内容看起来是 Go 指针，当前实现有时可能会导致运行时错误。因此，如果 Go 代码要在其中存储指针值，请避免将未初始化的 C 内存传递给 Go 代码。在将 C 中的内存传递给 Go 之前将其清零。

### 特别案例

一些在 Go 中通常由指针类型表示的特殊 C 类型改为由 uintptr 表示。其中包括：

\1. Darwin 上的 *Ref 类型，植根于 CoreFoundation 的 CFTypeRef 类型。

\2. Java的JNI接口中的对象类型：

```java
jobject 
jclass 
jthrowable 
jstring 
jarray 
jbooleanArray 
jbyteArray 
jcharArray 
jshortArray 
jintArray 
jlongArray 
jfloatArray 
jdoubleArray 
jobjectArray 
jweak
```

\3. EGL API 中的 EGLDisplay 和 EGLConfig 类型。

这些类型在 Go 端是 uintptr，否则它们会混淆 Go 垃圾收集器；它们有时不是真正的指针，而是以指针类型编码的数据结构。对这些类型的所有操作都必须在 C 中进行。初始化此类空引用的正确常量是 0，而不是 nil。

这些特殊情况是在 Go 1.10 中引入的。对于 Go 1.9 及更早版本的自动更新代码，请使用 Go 修复工具中的 cftype 或 jni 重写：

```shell
go tool fix -r cftype <pkg> 
go tool fix -r jni <pkg>
```

它将在适当的地方用 0 替换 nil。

EGLDisplay 案例是在 Go 1.12 中引入的。使用 egl 重写来自动更新 Go 1.11 及更早版本的代码：

```shell
go tool fix -r egl <pkg>
```

EGLConfig 案例是在 Go 1.15 中引入的。使用 eglconf 重写来自动更新 Go 1.14 及更早版本的代码：

```
go tool fix -r eglconf <pkg>
```

### 直接使用 cgo

用法：

```shell
go tool cgo [cgo options] [--compiler options] gofiles...
```

Cgo 将指定的输入 Go 源文件转换为多个输出 Go 和 C 源文件。

当调用 C 编译器来编译包的 C 部分时，编译器选项会通过未解释的方式传递。

直接运行 cgo 时可以使用以下选项：

```shell
-V
	打印 cgo 版本并退出。
-debug-define
	调试选项。打印#defines。
-debug-gcc
	调试选项。跟踪 C 编译器的执行和输出。
-dynimport file
	写入由文件导入的符号列表。写入
	-dynout 参数或标准输出。go 
	build 在构建 cgo 包时使用。
-dynlinker
	将动态链接器编写为 -dynimport 输出的一部分。
-dynout 文件
	将 -dynimport 输出写入文件。
-dynpackage package
	为 -dynimport 输出设置 Go 包。
-exportheader file
	如果有任何导出函数，将
	生成的导出声明写入文件。
	C 代码可以#include this 来查看声明。
-importpath string 
	Go 包的导入路径。可选的; 用于
	生成文件中更好的注释。
-import_runtime_cgo
	如果设置（默认情况下）在
	生成的输出中导入 runtime/cgo。
-import_syscall
	如果设置（默认情况下）在
	生成的输出中导入系统调用。
-gccgo
	为 gccgo 编译器而不是
	gc 编译器生成输出。
-gccgoprefix prefix
	与 gccgo 一起使用的 -fgo-prefix 选项。
-gccgopkgpath path
	与 gccgo 一起使用的 -fgo-pkgpath 选项。
-godefs
	用 Go 语法写出输入文件，
	用实际值替换 C 包名称。用于
	在引导新目标时在 syscall 包中生成文件。
-objdir directory
	将所有生成的文件放在目录中。
-srcdir 目录
```