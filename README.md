# Tunnel-Manager

Why made it?

You should use config.json to establish new tunnels. But if you want to manually start ssh tunnels, make sure you include the bind_address (`-R [bind_address:]port:host:hostport`) in your command so that SSH-Tunnels-Manager can monitor it.
Ex: `ssh -N -i /home/user/.ssh/aws_key_1.pem -R 0.0.0.0:433:0.0.0.0:433 root@192.168.1.1`

GoJS is a dependency that is up to you to download. It offers pretty nice visualizations. You can download it from here https://gojs.net/latest/download.html and copy it to application/static/go.js. 

