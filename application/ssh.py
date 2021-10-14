"""
https://github.com/M507
"""

from config import *
from common import *


def list_ps():
    ssh_sessions = []
    for proc in psutil.process_iter():
        if proc.name() == "ssh":
            ssh_sessions .append(proc)
            # command = proc.cmdline()
            # command = ' '.join(command)
            # pid = str(proc.pid)
    return ssh_sessions

def get_bindPort_hostPort(process):
    command = process.split('ssh ')[1]
    command = command.split(' ')
    bindPort, hostPort, ipaddress = None,None,None
    for chunk in command:
        if ':' in chunk:
            chunk = chunk.split(':')
            bindPort = chunk[1]
            hostPort = chunk[3]
        if '@' in chunk:
            chunk = chunk.split('@')
            #username = chunk[0]
            ipaddress = chunk[1]
    return bindPort, hostPort, ipaddress



def kill_a_session(ip, bindPort, hostPort):
    ssh_sessions = list_ps()
    for proc in ssh_sessions:
        pid = str(proc.pid)
        session = ' '.join(proc.cmdline())
        if ip in session:
            if ":" in session:
                bindPort_session, hostPort_session, ipaddress = get_bindPort_hostPort(session)
                debugMessage(str(bindPort_session)+" "+str(hostPort_session))
                if str(bindPort) == str(bindPort_session):
                    if str(hostPort) == str(hostPort_session):
                        os.kill(int(pid), signal.SIGKILL ) # signal.SIGTERM or signal.SIGKILL 
                        debugMessage(pid+" process has been killed. Session: "+session)

def list_alive_sessions():
    ssh_sessions = list_ps() 
    tmp_list = []
    for proc in ssh_sessions:
        pid = str(proc.pid)
        command_line_string = proc.cmdline()
        if "-R" in command_line_string:
            redirect_type = 1
        elif "-L" in command_line_string:
            redirect_type = 0
        else:
            redirect_type = -1
        session = ' '.join(command_line_string)
        if ":" in session:
            bindPort_session, hostPort_session, ipaddress = get_bindPort_hostPort(session)
            tmp_list.append([bindPort_session, hostPort_session, ipaddress, redirect_type])
    
    # Returns elemets that look like this:
    # [[88, 88, 21.21.45.54,1]]
    return tmp_list

def add_status_helper(tmp_list, config_data,key):
    for i in range(len(config_data[key])):
        config_data[key][i]['color'] = "gray"


    for i in range(len(tmp_list)):
        set_dead = 1
        session = tmp_list[i]
        alive_bindPort = session[0]
        alive_hostPort = session[1]
        alive_IPAddress = session[2]
        alive_redirect_type = session[3]

        if str(alive_redirect_type) == "1":
            key = "RemoteHosts"
        elif str(alive_redirect_type) == "0":
            key = "LocalHosts"
        else:
            debugMessage("Error! #99378464")

        for j in range(len(config_data[key])):
            if str(alive_hostPort) == str(config_data[key][j]['HostPort']):
                if str(alive_bindPort) == str(config_data[key][j]['BindPort']):
                    if str(alive_IPAddress) == str(config_data[key][j]['IPAddress']):
                        config_data[key][j]['status'] = "alive"
                        config_data[key][j]['color'] = "green"
                        set_dead = 0
                        tmp_list[i].append(set_dead)
                        break
    return tmp_list

def add_status(config_data):
    tmp_list = list_alive_sessions()
    # each element has [bindPort_session, hostPort_session, ipaddress, redirect_type]

    tmp_list = add_status_helper(tmp_list, config_data,"RemoteHosts")
    tmp_list = add_status_helper(tmp_list, config_data,"LocalHosts")
    
    # now for the unrecorded sessions
    for i in range(len(tmp_list)):
        session = tmp_list[i]
        if len(session) <= 4:
            alive_bindPort = session[0]
            alive_hostPort = session[1]
            alive_IPAddress = session[2]
            alive_redirect_type = session[3]

            debugMessage(str(alive_IPAddress + " " + str(alive_hostPort)+ " " + str(alive_bindPort)+ " "+ str(alive_redirect_type)+ " " ))
            new_unrecorded_session = {
                "IPAddress":alive_IPAddress,
                "BindPort":alive_bindPort,
                "HostPort":alive_hostPort,
                "status":"alive",
                "Type":"Unknown",
                "Username":"Unknown",
                "Key":"Unknown",
                "redirect_type":alive_redirect_type,
                "color":"green"
                }
            if str(alive_redirect_type) == "1":
                config_data['RemoteHosts'].append(new_unrecorded_session)
            elif str(alive_redirect_type) == "0":
                config_data['LocalHosts'].append(new_unrecorded_session)
    return config_data


def remove_duplicates(config_data):
    tmp_l = []
    tobe_removed = []
    for i in range(len(config_data['RemoteHosts'])):
        p = config_data['RemoteHosts'][i]
        tmp1 = p["IPAddress"]
        tmp1 += p["BindPort"]
        tmp1 += p["HostPort"]
        if tmp1 in tmp_l:
            tobe_removed.append(i)
            pass
        else:
            tmp_l.append(tmp1)

    for ind in tobe_removed:
        config_data['RemoteHosts'].pop(ind)
    return config_data

def connect_tunnle(key,bind_address,BindPort,host,HostPort,username,ip, root=None):
    #command = "ssh -v -f -N -i "+SSH_KEYS+f"{key} -R {bind_address}:{BindPort}:{host}:{HostPort} {username}@{ip} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5"
    command = "ssh -N -i "+SSH_KEYS+f"{key} -R {bind_address}:{BindPort}:{host}:{HostPort} {username}@{ip} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -o StrictHostKeyChecking=no &"
    if root:
        command = "ssh -N -i "+SSH_KEYS+f"{key} -R {bind_address}:{BindPort}:{host}:{HostPort} root@{ip} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -o StrictHostKeyChecking=no &"

    # log the -v output
    debugMessage("Executing: "+command)
    #subprocess.Popen(command.split(' '))
    os.system(command)

def connect_tunnle_local(key,bind_address,BindPort,host,HostPort,username,ip, root=None):
    command = "ssh -N -i "+SSH_KEYS+f"{key} -L {bind_address}:{BindPort}:{host}:{HostPort} {username}@{ip} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -o StrictHostKeyChecking=no &"
    if root:
        command = "ssh -N -i "+SSH_KEYS+f"{key} -L {bind_address}:{BindPort}:{host}:{HostPort} root@{ip} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -o StrictHostKeyChecking=no &"
    # log the -v output
    debugMessage("Executing: "+command)
    #subprocess.Popen(command.split(' '))
    os.system(command)

# This function has been tested on Ubuntu
# This should allow using root. Please have strict firewall rules.
def reconfigure_ssh(key,username,ip):
    command = f"""ssh -o StrictHostKeyChecking=no -i {SSH_KEYS}{key} {username}@{ip}  'bash -s' < """+FLASK_DIR+"""/scripts/enable_port_forwarding.sh"""

    # log the -v output
    debugMessage("Executing: "+command)
    os.system(command)
    #subprocess.Popen(command.split(' '))


def connect_all(config_data):
    Hosts = config_data['RemoteHosts']
    for element in Hosts:
        IPAddress = element['IPAddress']
        Type = element['Type']
        Username = element['Username']
        Key = element['Key']
        BindPort = element['BindPort']
        HostPort = element['HostPort']
        Username = element['Username']
        Username = element['Username']
        connect_tunnle(Key,"0.0.0.0",BindPort,"0.0.0.0",HostPort,Username,IPAddress)

    LocalHosts = config_data['LocalHosts']
    for element in LocalHosts:
        IPAddress = element['IPAddress']
        Type = element['Type']
        Username = element['Username']
        Key = element['Key']
        BindPort = element['BindPort']
        HostPort = element['HostPort']
        Username = element['Username']
        Username = element['Username']
        connect_tunnle_local(Key,"0.0.0.0",BindPort,"0.0.0.0",HostPort,Username,IPAddress)

