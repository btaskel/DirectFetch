## DirectFetch 绕过SNI封锁的简单文件下载器

### 前言：

只是我练习网络编程的小项目，该项目可以让你**绕过**非法对SNI封锁严厉的地区，请不要将其用于违法用途，仅供学习。

例如下载 https://downloadxxxx.mediafire.com/.../test_file.rar 它将被阻断，除非你使用代理软件。

DirectFetch 可以在无需使用代理软件的情况下下载特定文件。

支持断点继传，实时显示进度，如果因为网络波动断开连接了没事，可以再次启动程序，它会自动根据上一次进度下载。

### 使用方法

#### 直接使用：
    1. 下载 DirectFetch Releases
    2. 在 config.json 中将 target_url 更改为你要下载的文件地址
    3. 运行 DirectFetch.exe

#### 编译：
    1. go mod tidy
    2. go build
    3. .\DirectFetch.exe
