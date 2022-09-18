# Tunnel-Manager

Why did I make this? Because I need:
- A fast way to replace burned IPs.
- An easy way to spawn up and destroy tunnels on AWS.
- Persistent tunnel configurations.
- Shareable configurations.
- Visualization of the network flow.


For more details: <a style="color:#c0c0c0" href="https://shellcode.blog/Using-Cobalt-Strike-with-Tunnel-Manager-for-Distributed-Hacking/"> Using Cobalt Strike with Tunnel-Manager for Distributed Hacking </a>



### The tool's GUI
![.](https://shellcode.blog/images/Cobalt-Strike/1/g3.png)


## Installation

To properly launch the application:

- Use `variables.env.example` to create your own `variables.env` file. The file must be in the project's root directory.
- GoJS is a dependency that is up to you to download. It offers pretty nice visualizations. You can download it from here https://gojs.net/latest/download.html and copy it to application/static/go.js. 
- Run install.sh to install the app's dependencies
