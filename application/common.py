"""
https://github.com/M507
"""

import sys
from config import *
from globalvars import *

def debugMessage(q):
    """
    :param q: a string
    :return: None
    """
    print("Debug Message :" + str(q), file=sys.stderr)



def send_errer(error_message, url_for):
    if debug:
        debugMessage(error_message)
    return render_template('error.html', message=error_message, url=url_for('competitions_team'),
                           templates_length=getTemplatesLength(), tasks_length=getEventsLength())

def read_a_file_and_get_all_lines(file_name):
    try:
        with open(file_name,'r') as f:
            output = f.read()
        lines = output.split('\n')
        return lines
    except Exception as e:
        print( "Error 432: read_a_file_and_get_all_lines function " + str(e))
        return None


def append_to_a_file(file_name, line):
    try:
        file1 = open(file_name, "a")  # append mode 
        file1.write(line+"\n") 
        file1.close()
        return 1
    except Exception as e:
        print( "Error: append_to_a_file function " + str(e))
        file1.close()
        return 0


def write_lines(file_name, lines):
    try:
        f = open(file_name, "a")
        f.writelines(lines)
        f.close()
        return 1
    except Exception as e:
        print( "Error: write_lines function " + str(e))
        f.close()
        return 0


def os_execute_command(command):
    """
    Execute command locally
    :param command:
    :return: stdout
    """
    if len(command) > 0:
        print(command)
        os.system(command)


def subprocess_execute_command(command, timeout = None):
    """
    Execute command locally
    :param command:
    :return: stdout
    """
    try:
        if len(command) > 0:
            command = command.split(' ')
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if timeout is not None:
                try:
                    process.wait(timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
            return stdout
    except:
        raise ValueError(
            'subprocess_execute_command returned an error \n'
        )


def subprocess_execute_command_pip(command1, command2, timeout = None):
    """
    Execute command locally
    :param command:
    :return: stdout
    """
    try:
        if len(command1) > 0:
            command1 = command1.split(' ')
            command2 = command2.split(' ')
            #process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc1 = subprocess.Popen(command1, stdout=subprocess.PIPE)
            proc2 = subprocess.Popen(command2, stdin=proc1.stdout,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc2.communicate()
            if timeout is not None:
                try:
                    process.wait(timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
            return stdout
    except:
        raise ValueError(
            'subprocess_execute_command returned an error \n'
        )


def send_error(variable, variable_name, function_name):
    if debug:
        error_message = "Missing "+ variable_name
        debugMessage(error_message)
    return render_template('error.html', message = error_message ,url = url_for(function_name))


def check_if_exists(variable, variable_name, function_name):
    try:
        # Condition #1 is when variable is None
        if variable is None:
            send_error(variable, variable_name, function_name)
            return 1
        # Condition #2 is when variable is empty
        if len(variable) < 1:
            send_error(variable, variable_name, function_name)
            return 1
    except:
        send_error(variable, variable_name, function_name)
        return 1
    return 0


def read_config(example_path = "config.json"):
    f = open(example_path)
    data = json.load(f)
    f.close()
    return data


def overwrite_vars(json_data):
    try:
        with open(FLASK_DIR+'/config.json', 'w') as outfile:
            json.dump(json_data, outfile)
    except Exception as e:
        print( "Error: write_lines function " + str(e))


def filter_using_regex(lines, pattern = "^ssh .*@.*"):
    re_pattern = re.compile(pattern)
    ssh_sessions = []
    for line in lines:
        line = str(line).strip()
        line = re.sub(' +', ' ', line)
        if re_pattern.match(line):
            # remove multiple spaces in a string
            ssh_sessions.append(line)
    return ssh_sessions


def sanitize(STRING_VAR, reg_condition = '[^A-Za-z0-9]+'):
    return re.sub(reg_condition, '', STRING_VAR)

def add_redirect_type(hosts,type_var):
    # if redirect_type is 1 that means it's a remote redirect 
    try:
        for host in hosts:
            host['redirect_type'] = type_var
        return hosts
    except:
        return []