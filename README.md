# keytabExtractor2

Fully based on the original https://github.com/sosdave/KeyTabExtract. 

Fixing the old tool which only dumped one entry from a keytab file then stopped. This could be painful if you need a host/SERVER key but the first key belongs to nfs, for example.

Original tool:<br>
![KeyTabExtract](pic/pic01.png)

keytabExtractor2 with the same keytab file:<br>
![keytabExtractor2](pic/pic02.png)
![keytabExtractor2](pic/pic03.png)
It is useful if you need a key for a specific service, such as nfs, http, host, cifs, etc.
