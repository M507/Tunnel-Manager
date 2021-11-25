echo "Create a cert" 
openssl req -x509 -newkey rsa:4096 -nodes -out application/cert.pem -keyout application/key.pem -days 365
echo "Install python3 dependencies" 
apt install python3-pip -y
pip3 install -r application/requirements.txt
# additions
pip3 install boto3
pip3 install awscli