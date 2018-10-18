# close\_pid\_socket

Close a socket owned by another pid.

```
close_pid_socket <pid> <socket_fd>
```
The `pid` and `socket_fd` of a connection can be found with the command `ss -ntpau`.
