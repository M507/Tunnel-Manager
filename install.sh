echo "Create a cert" 
openssl req -x509 -newkey rsa:4096 -nodes -out application/cert.pem -keyout application/key.pem -days 365
echo "Install python3 dependencies" 
apt install python3-pip -y
pip3 install -r application/requirements.txt
chmod ao-w application/config.json

# sudo apt-get install software-properties-common -y
# apt-add-repository ppa:ansible/ansible
# sudo apt-get update -y
# sudo apt-get install ansible -y
# sudo pip3 install ansible
# ansible -version

pip3 install boto3

pip3 install awscli



