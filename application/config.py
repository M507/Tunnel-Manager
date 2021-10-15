"""
https://github.com/M507
"""

debug = 1

import sys, ipaddress, os, datetime, pymongo, threading, json, string, random, re, time, ipaddress, subprocess,re, requests, signal, psutil, glob
from flask import Flask, flash, render_template, request, session, redirect, url_for, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import *
#from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from flask import jsonify
from dotenv import load_dotenv
from random import choice
from string import ascii_uppercase
import logging, logging.config, yaml
from globalvars import *


# Get the dir name
#APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Flask app
app = Flask(__name__, template_folder = FLASK_TEMPLATES_FOLDER)
app._static_folder = FLASK_STATIC_FILES_FOLDER

# import logging configuration
logging.config.dictConfig(yaml.load(open('logging.conf')))

logfile    = logging.getLogger('file')
logconsole = logging.getLogger('console')
logfile.debug("Debug FILE")
logconsole.debug("Debug CONSOLE")

# Get env variables
load_dotenv(dotenv_path=ENV_VARIABLES)

# Slack
WEBHOOK_URL = os.environ.get('WEBHOOK_URL')

# SSH
SSH_KEYS = ROOT_DIR + "/keys/"
SSH_KEYS_tmp = os.environ.get('SSH_KEYS')
if SSH_KEYS_tmp != "default":
    SSH_KEYS = SSH_KEYS_tmp

# AWS keys
ACCESS_KEY = os.environ.get('aws_access_key')
SECRET_KEY = os.environ.get('aws_secret_key')

# Instance info
SSHKEYNAME = os.environ.get('SSHKeyName')
SUBNETID = os.environ.get('SubnetId')
SECURITYGROUPID = os.environ.get('SecurityGroupId')
IMAGEID = os.environ.get('ImageId')
INSTANCE_USERNAME = os.environ.get('Instance_username')

# Rate limit
Limiter.enabled = False

# Creating Sessions
secretKey = os.urandom(24)
app.secret_key = secretKey

# Configure CORS
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app)
