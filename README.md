# chat

* peer-to-peer messaging
* broadcast messages
* public messages
    ```
    just type messages into stdin, and all your peers will receive it!
    ```
    ```
    main.Message{ID:"74a283c6f347f2c5", Name:"Anonimous", Addr:"127.0.0.1:8001", Body:"just type messages into stdin, and all your peers will receive it!"}
    ```
* private messages
    ```
    ip:port|message
    ```
* private messages encryption (AES). Note: key should be 16, 24 or 32 bytes long
* anti-spam feature (looking for spam in body)
* peer name at start up

## build

```
go build -o chat
```

## run

```
$ ./chat --myname user3 --listen 127.0.0.1:8003 --peer 127.0.0.1:8002 -aeskey="very-secure-key1"
2018/03/31 21:32:25 Using name: user3
2018/03/31 21:32:25 Listening on 127.0.0.1:8003
2018/03/31 21:32:25 Connected to 127.0.0.1:8002
127.0.0.1:8002|encrypted private message
127.0.0.1:8001|another encrypted private message


$ ./chat --myname user2 --listen 127.0.0.1:8002 --peer 127.0.0.1:8001 -aeskey="very-secure-key1"
2018/03/31 21:32:22 Using name: user2
2018/03/31 21:32:22 Listening on 127.0.0.1:8002
2018/03/31 21:32:22 Connected to 127.0.0.1:8001
2018/03/31 21:32:36 Incoming private connection from: user3 127.0.0.1:8003
main.Message{ID:"e56e6a0fb4d8d53a", Name:"user3", Addr:"127.0.0.1:8003", Body:"encrypted private message", Recipient:"127.0.0.1:8002"}
2018/03/31 21:32:36 Connected to 127.0.0.1:8003


$ ./chat --myname user1 --listen 127.0.0.1:8001
2018/03/31 21:32:18 Using name: user1
2018/03/31 21:32:18 Listening on 127.0.0.1:8001
2018/03/31 21:32:45 Incoming private connection from: user3 127.0.0.1:8003
main.Message{ID:"f59aa2e3a05424a1", Name:"user3", Addr:"127.0.0.1:8003", Body:";\xfa\xec\xbdN_\xaf\xc4b\x86\\\x06\xd0U\xc6G\xf0kK\xb9\xf3L\xc4\xe1\xde8\xb9[\x1a\x82\x81\x96$", Recipient:"127.0.0.1:8001"}
2018/03/31 21:32:45 Connected to 127.0.0.1:8003
```