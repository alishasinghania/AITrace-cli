"""Command-execution sinks versus lookalikes."""

from flask import request
from helper import run_cmd
import os
import subprocess


def user_to_system():
    msg = request.json["cmd"]
    os.system("echo " + msg)  # gt:FLOW-RCE:confirmed_taint


def constant_command():
    os.system("echo hello")  # gt:FLOW-RCE:absent


def resolved_helper():
    msg = request.json["cmd"]
    run_cmd(msg)


def unresolved_wrapper():
    msg = request.json["cmd"]
    y = mystery(msg)
    os.system(y)  # gt:FLOW-RCE:absent


def unrelated_system_name():
    msg = request.json["cmd"]
    logger.system(msg)  # gt:FLOW-RCE:absent


def safe_subprocess():
    subprocess.run(["echo", "hello"])  # gt:FLOW-RCE:absent
