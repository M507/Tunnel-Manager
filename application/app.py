"""
https://github.com/M507
"""

from config import *
from ssh import *
from slack import *
from botoClient import *

ssh_sessions = list_ps()
ssh_sessions = [ ' '.join(proc.cmdline()) for proc in ssh_sessions]
config_data = read_config()

if config_data['autoreconnect']:
    connect_all(config_data)

def check_if_missing(ssh_sessions):
    ssh_sessions_tmp = list_ps()
    ssh_sessions_tmp = [ ' '.join(proc.cmdline()) for proc in ssh_sessions_tmp]
    Missing_vals = (set(ssh_sessions).difference(ssh_sessions_tmp))
    debugMessage("Missing values in second list:"+ str(Missing_vals))
    #print("Additional values in second list:", (set(list2).difference(list1)))

    for disconnection in Missing_vals:
        slack_notify("Interface "+ disconnection+" is disconnected")

def logical_xor(str1, str2):
    return bool(str1) ^ bool(str2)

def get_addresses(config_data):
    hosts = config_data['RemoteHosts']
    ips = []
    for host in hosts:
        ips.append(host['IPAddress'])

    hosts = config_data['LocalHosts']
    for host in hosts:
        ips.append(host['IPAddress'])
    
    ips = list(dict.fromkeys(ips))
    return ips

def get_address_vars(IPADDRESS, BINDPORT, HOSTPORT, config_data):
    # The following block of code is in the case that I want to get ONLY the ssh key name 
    # and username and I don't care about values of the ports. 
    do_verify = 1
    try:
        if BINDPORT is None:
            if HOSTPORT is None:
                do_verify = 0
    except:
        do_verify = 1

    for host in config_data['RemoteHosts']:
        if IPADDRESS == host['IPAddress']:
            if do_verify:
                if HOSTPORT == host['HostPort']:
                    if BINDPORT == host['BindPort']:
                        return host, 1
            else:
                return host, 1
    for host in config_data['LocalHosts']:
        if IPADDRESS == host['IPAddress']:
            if do_verify:
                if HOSTPORT == host['HostPort']:
                    if BINDPORT == host['BindPort']:
                        return host, 0
            else:
                return host, 0

def session_edit(IPADDRESS, BINDPORT, HOSTPORT, config_data, reconnect_tunnle = False):
    if  len(IPADDRESS) > 0:
        if  len(BINDPORT) > 0:
            if  len(HOSTPORT) > 0:
                # debugMessage(IPADDRESS)
                # debugMessage(BINDPORT)
                # debugMessage(HOSTPORT)
                host, direction = get_address_vars(IPADDRESS, BINDPORT, HOSTPORT, config_data)
                debugMessage(str(IPADDRESS)+ " was found to edit")
                debugMessage("About to kill "+ str(host))
                kill_a_session(host['IPAddress'],host['BindPort'], host['HostPort'])
                if reconnect_tunnle:
                    time.sleep(5)
                    # if direction is 1 that means it's a remote redirect 
                    if direction == 1:
                        connect_tunnle(host['Key'],"0.0.0.0",host['BindPort'],"0.0.0.0",host['HostPort'],host['Username'], host['IPAddress'])
                    if direction == 0:
                        connect_tunnle_local(host['Key'],"0.0.0.0",host['BindPort'],"0.0.0.0",host['HostPort'],host['Username'], host['IPAddress'])
                return 1
    return 0

def CreateNode_helper(config_data, SSH_KEY,BINDPORT,HOSTPORT,INSTANCE_USERNAME):
    public_ip_address = "127.0.0.2"
    public_ip_address = create_instance()

    # Reconfigure SSH
    reconfigure_ssh(SSH_KEY,INSTANCE_USERNAME,public_ip_address)
    
    # Connect using root
    connect_tunnle(SSH_KEY,"0.0.0.0",BINDPORT,"0.0.0.0",HOSTPORT,INSTANCE_USERNAME,public_ip_address, root=True)

    # From now and on...only use root to connect to aws nodes
    new_unrecorded_session = {
                "IPAddress":public_ip_address,
                "BindPort":BINDPORT,
                "HostPort":HOSTPORT,
                "status":"alive",
                "Type":"Unknown",
                # It needs root to connect - I meannnn .. just going to hack my way in : ) 
                "Username":"root",
                #"Username":INSTANCE_USERNAME,
                "Key":SSH_KEY,
                "color":"green"
                }
    config_data['RemoteHosts'].append(new_unrecorded_session)

    debugMessage(config_data['RemoteHosts'][-1])
    overwrite_vars(config_data)
    return 0


@app.route("/CreateNode", methods=['GET'])
def CreateNode():
    """
    Notes 1:
    Asking the user about the direction of the connection is useless 
    since I don't think there is any reason to use remote port forwarding and local port forwarding at the same time on the same host!
    so I will not add anything to handle that. 
    I will assume that if the ip already exists in your config that means that you want to use the same dirrection. 
    """
    global ssh_sessions
    global config_data
    config_data = read_config()

    #request.form.get("fieldname")

    IPADDRESS = request.args.get('IPAddress', default = "")
    IPADDRESS = IPADDRESS.translate(str.maketrans('', '', '!"#$%&\'()*+,/:;<=>?@[\]^_`{|}~'))
    IPADDRESS = IPADDRESS.lower().replace('new','')

    BINDPORT = request.args.get('BindPort', default = "")
    HOSTPORT = request.args.get('HostPort', default = "")
    SSH_KEY = request.args.get('SSHKey', default = "")
    BINDPORT = sanitize(BINDPORT, reg_condition = '[^A-Za-z0-9]+')
    HOSTPORT = sanitize(HOSTPORT, reg_condition = '[^A-Za-z0-9]+')
    SSH_KEY = SSH_KEY.translate(str.maketrans('', '', '!"#$%&\'()*+,/:;<=>?@[\]^_`{|}~'))

    debugMessage(IPADDRESS)
    debugMessage(BINDPORT)
    debugMessage(HOSTPORT)
    debugMessage(SSH_KEY)


    for element in [BINDPORT, HOSTPORT, SSH_KEY]:
        if len(element) == 0:
            # TODO: SHOW ERROR
            return redirect(url_for('root'))
    
    if len(IPADDRESS) <= 1:
        #CreateNode_helper(config_data, SSH_KEY,BINDPORT,HOSTPORT,INSTANCE_USERNAME)
        t = threading.Thread(target=CreateNode_helper, args=(config_data, SSH_KEY,BINDPORT,HOSTPORT,INSTANCE_USERNAME))
        t.start()
    else:
        IPAddresses = get_addresses(config_data)
        # This means we want to establish a new tunnel
        if IPADDRESS in IPAddresses:
            host, direction = get_address_vars(IPADDRESS, None, None, config_data)
            # Note 1, check the above notes
            if direction == 1:
                connect_tunnle(host['Key'],"0.0.0.0",BINDPORT,"0.0.0.0",HOSTPORT,host['Username'], host['IPAddress'])
            if direction == 0:
                connect_tunnle_local(host['Key'],"0.0.0.0",BINDPORT,"0.0.0.0",HOSTPORT,host['Username'], host['IPAddress'])
    
    return redirect(url_for('root'))



@app.route("/", methods=['GET'])
def root():
    global ssh_sessions
    global config_data
    """
    Root
    :return:
    """
    config_data = read_config()

    AUTORECONNECT = request.args.get('Autoreconnect', default = "")
    AUTORECONNECT = re.sub('[^A-Za-z0-9]+', '', AUTORECONNECT)
    if len(AUTORECONNECT) > 0:
        if config_data['autoreconnect'] != AUTORECONNECT:
            xor_value = logical_xor(AUTORECONNECT,1)
            if xor_value == True:
                config_data['autoreconnect'] = 1
            if xor_value == False:
                config_data['autoreconnect'] = 0
            # Save
            overwrite_vars(config_data)
    
    IPADDRESS = request.args.get('IPAddress', default = "")
    BINDPORT = request.args.get('BindPort', default = "")
    HOSTPORT = request.args.get('HostPort', default = "")
    RECONNECT = request.args.get('Reconnect', default = "")

    BINDPORT = sanitize(BINDPORT, reg_condition = '[^A-Za-z0-9]+')
    HOSTPORT = sanitize(HOSTPORT, reg_condition = '[^A-Za-z0-9]+')
    RECONNECT = sanitize(RECONNECT, reg_condition = '[^A-Za-z0-9]+')

    # \/ customized string.punctuation
    IPADDRESS = IPADDRESS.translate(str.maketrans('', '', '!"#$%&\'()*+,/:;<=>?@[\]^_`{|}~'))

    if RECONNECT == "1":
        RECONNECT = True
    else:
        RECONNECT = False
    if session_edit(IPADDRESS, BINDPORT, HOSTPORT, config_data, RECONNECT):
        return redirect(url_for('root'))

    #check_if_missing(ssh_sessions)
    
    #ssh_sessions = list_ps()
    #ssh_sessions = [ ' '.join(proc.cmdline()) for proc in ssh_sessions]
    
    config_data = add_status(config_data)
    config_data = remove_duplicates(config_data)
    hosts_tmp = config_data["RemoteHosts"]
    hosts = add_redirect_type(hosts_tmp,"R")
    hosts_tmp = config_data["LocalHosts"]
    hosts += add_redirect_type(hosts_tmp,"L")

    IPAddresses = get_addresses(config_data)

    keys = get_all_keys()

    return render_template('index.html', ssh_sessions = hosts, IPAddresses = IPAddresses, keys = keys)


if __name__ == "__main__":
    # import declared routes
    from common import *
    from globalvars import *


    app.run(host='0.0.0.0', port = 5000 ,ssl_context=(FLASK_CERT, FLASK_KEY))   