# keytabExtractor2

Fully based on the original https://github.com/sosdave/KeyTabExtract. 

Fixing the old tool which only dumped one entry from a keytab file then stopped.

Original tool:<br>
![KeyTabExtract](pic/pic01.png)

keytabExtractor2 with the same keytab file:<br>
![keytabExtractor2](pic/pic02.png)

It is useful if you need a key for multiple services, such as nfs, http, host, cifs, etc.
For example, when abusing unconstrained delegation on linux.
