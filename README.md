# close\_pid\_socket

Close a socket owned by another process, without (forcefully) killing that process.

```
close_pid_socket <pid> <socket_fd>
```

The `pid` and `socket_fd` of a connection can be found with the command `ss -ntpau`.

Be aware that the process being handled might be terminated when the socket is unexpectedly
closed.
