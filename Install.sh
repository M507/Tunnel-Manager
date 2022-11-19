echo "Create a cert" 
openssl req -x509 -newkey rsa:4096 -nodes -out application/cert.pem -keyout application/key.pem -days 365 -subj "/C=US/ST=NY/L=NY/O=AAA Inc. /OU=IT Department/CN=AAA.com"
echo "Install python3 dependencies" 
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt-get update -y
# sudo apt-get install python3.7 -y
# curl -O https://bootstrap.pypa.io/get-pip.py
# sudo python3.7 get-pip.py
sudo apt install python3-pip -y
sudo pip3 install -r application/requirements.txt
cp application/config.json.example application/config.json