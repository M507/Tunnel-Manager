sudo bash -c 'cat /home/ubuntu/.ssh/authorized_keys > /root/.ssh/authorized_keys'
sudo sed 's/.*#PermitRootLogin.*prohibit\-password/PermitRootLogin yes/' /etc/ssh/sshd_config > /tmp/sshd_config.bk;
sudo sed 's/.*#GatewayPorts.*no/GatewayPorts yes/' /tmp/sshd_config.bk > /tmp/sshd_config.bk2;
sudo mv /tmp/sshd_config.bk2 /etc/ssh/sshd_config;
sudo systemctl restart ssh;