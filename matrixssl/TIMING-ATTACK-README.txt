Kompilieren:

$ cd SSL/matrixssl
$ make debug
$ cd apps
$ make debug


Verwenden:
$ cd SSL/matrixssl/apps
$ ./client base64(encrypted_PMS)

--> Der Client macht dann eine Verbindung zu localhost:4433 auf
