import argparse
import concurrent.futures
import io
import logging
import operator
import os
import shlex
import socket
import subprocess
import sys
import time
import xmlrpc.client

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

import argcomplete
import paramiko
import yaml
from colorama import Fore


def is_master_online(master_uri=None):
    """
    @param master_uri: (optional) override environment's ROS_MASTER_URI
    @type  master_uri: str
    @return: True if Master is available
    """

    # taken from here, but without needing full ros dependency
    # https://github.com/ros/ros_comm/blob/f5fa3a168760d62e9693f10dcb9adfffc6132d22/tools/rosgraph/src/rosgraph/masterapi.py#L74-L80

    DEFAULT_MASTER_PORT = 11311  # default port for master's to bind to
    DEFAULT_MASTER_URI = 'http://localhost:%s/' % DEFAULT_MASTER_PORT

    if master_uri is None:
        master_uri = os.getenv("ROS_MASTER_URI", DEFAULT_MASTER_URI)

    # doesn't support ROS namespaces
    caller_id = "robmuxinator"

    handle = xmlrpc.client.ServerProxy(master_uri)

    try:
        code, msg, val = handle.getPid(caller_id)
        logger.debug(f"[is_master_online] code: '{code}', msg: '{msg}', val: {val}")
        return bool(code == 1)
    except Exception as e:
        logger.debug(f"[is_master_online] exception: {e}")
        return False


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    green = Fore.GREEN
    yellow = Fore.YELLOW
    red = Fore.RED
    bold_red = Fore.RED
    cyan = Fore.CYAN
    reset = Fore.RESET
    form = "[%(levelname)s] [%(asctime)s]: %(message)s"

    FORMATS = {
        logging.DEBUG: green + form + reset,
        logging.INFO: form,
        logging.WARNING: yellow + form + reset,
        logging.ERROR: red + form + reset,
        logging.CRITICAL: bold_red + form + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logging.addLevelName(logging.DEBUG, "D")
logging.addLevelName(logging.INFO, "I")
logging.addLevelName(logging.WARNING, "W")
logging.addLevelName(logging.ERROR, "E")
logging.addLevelName(logging.CRITICAL, "C")

logger = logging.getLogger(__name__)

custom_format = CustomFormatter()

streamHandler = logging.StreamHandler(sys.stdout)
streamHandler.setFormatter(custom_format)
logger.addHandler(streamHandler)

logPath = "/var/log"
if not os.access(logPath, os.W_OK):
    logPath = os.path.expanduser("~/log")
if not os.path.exists(logPath):
    os.makedirs(logPath)
logFile = "robmuxinator"
fileHandler = RotatingFileHandler(
    "{0}/{1}.log".format(logPath, logFile), maxBytes=1024*10000, backupCount=4)
log_formatter = logging.Formatter("[%(levelname)s] [%(created)0.15s]: %(message)s")
fileHandler.setFormatter(log_formatter)
logger.addHandler(fileHandler)

paramiko_version_major = int(paramiko.__version__.split(".")[0])
paramiko_version_minor = int(paramiko.__version__.split(".")[1])

# check paramiko version to handle all ssh keys conrrectly
if paramiko_version_major <= 2 and paramiko_version_minor < 11:
    logger.error(
        'Incompatible paramiko version installed! Update the version with \n\tsudo -H pip3 install --upgrade "paramiko>=2.10"'
    )
    exit(1)

DEFAULT_USER = "robot"
DEFAULT_HOST = socket.gethostname()
DEFAULT_PORT = None  # default port None disables port check
DEFAULT_SSH_PORT = 22


class SSHClient:
    """Handle commands over ssh tunnel"""

    def __init__(self, user, hostname, port=DEFAULT_SSH_PORT):
        self._user = user
        self._hostname = hostname
        self._port = port

        # check if user has sudo privileges
        self._sudo_user = True if os.getuid() == 0 else False

        self._use_local_connection = self._hostname in ["localhost", "127.0.0.1"] \
            and self._user == os.getenv("USER", "INVALID_USER")

        # TODO: handle exceptions
        self.ssh_cli = None

    def init_connection(self):
        if self.ssh_cli is None:
            key_filename=""
            key_candidates=["id_ed25519", "id_rsa"]
            for key in key_candidates:
                key_filename = os.path.expanduser(f"~/.ssh/{key}")
                if os.path.isfile(key_filename):
                    logger.debug(f"  using key_filename '{key_filename}'")
                    break
            else:
                raise Exception(f"  no key_file found among candidates {key_candidates}")

            try:
                self.ssh_cli = paramiko.client.SSHClient()
                self.ssh_cli.load_system_host_keys()
                self.ssh_cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_cli.connect(
                    username=self._user,
                    hostname=self._hostname,
                    port=self._port,
                    key_filename=key_filename,
                    disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
                )
            except (
                paramiko.ssh_exception.SSHException,
                paramiko.ssh_exception.NoValidConnectionsError,
            ) as e:
                logger.error("  SSH Error: {}".format(e))
                raise e
            except ValueError as ve:
                if str(ve).startswith("q must be exactly"):
                    raise Exception("  Check the correctness of SSH key for user '{}' on host '{}'".format(self._user, self._hostname))
                else:
                    raise ve

    def send_cmd(self, cmd, wait_for_exit_status=True, get_pty=False):
        start = datetime.now()
        try:
            returncode = 0
            if not self._use_local_connection:
                self.init_connection()
                stdin, stdout, stderr = self.ssh_cli.exec_command(cmd, get_pty=get_pty)
                logger.debug(f"{cmd}")
                if wait_for_exit_status:
                    returncode = stdout.channel.recv_exit_status()

                stdout = stdout.read().decode()
                stderr = stderr.read().decode()
            else:
                logger.debug("  using local connection")
                process = subprocess.Popen([cmd],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            shell=True,
                                            text=True)

                if wait_for_exit_status:
                    stdout, stderr = process.communicate()
                    returncode = process.returncode
                else:
                    stdout = process.stdout.read()
                    stderr = process.stderr.read()

            logger.debug(
                "send_cmd: {}  took {} secs".format(
                    cmd, (datetime.now() - start).total_seconds()
                )
            )
            return returncode, stdout, stderr
        except Exception as e:
            logger.error("{}".format(e))
            self.ssh_cli = None
            return 1, None, None

    def send_keys(self, session_name, keys):
        cmd = "tmux send-keys -t {} {} ENTER".format(session_name, shlex.quote(keys))
        returncode, stdout, stderr = self.send_cmd(cmd)
        return not returncode

    def has_session(self, session_name):
        cmd = "tmux has-session -t {}".format(session_name)
        returncode, stdout, stderr = self.send_cmd(cmd)
        return not returncode

    def new_session(self, session_name):
        cmd = "tmux new -d -s {}".format(session_name)
        returncode, stdout, stderr = self.send_cmd(cmd)
        return not returncode

    def kill_session(self, session_name):
        cmd = "tmux kill-session -t {}".format(session_name)
        returncode, stdout, stderr = self.send_cmd(cmd)
        return not returncode

    def stop_session(self, session_name):
        # get pid
        cmd = r"tmux list-panes -s -F \"#{pane_pid}\" -t " + session_name
        returncode, stdout, stderr = self.send_cmd(cmd)
        pid = None
        pid_session = None

        if not returncode:
            pid_session = stdout.rstrip("\n") if len(stdout) > 0 else None
            if pid_session:
                cmd = "pgrep -P {}".format(pid_session)
                returncode, stdout, stderr = self.send_cmd(cmd)
                pid = stdout.rstrip("\n") if len(stdout) > 0 else None
                if not pid:
                    logger.error(f"  session {session_name}: could not get process pid for session pid")
            else:
                logger.error(f"  session {session_name}: could not get process pid for session pane pid {pid_session}")
        else:
            logger.error(f"  session {session_name}: command to get session pane_pid failed with returncode {returncode}")

        cmd = "tmux send -t {} C-c".format(session_name)

        returncode, stdout, stderr = self.send_cmd(cmd)

        if pid:
            cmd = "ps -p {} > /dev/null".format(pid)
            logger.info(
                "  session {}: waiting 30 sec for process with pid {} to stop".format(
                    session_name, pid
                )
            )
            end = datetime.now() + timedelta(seconds=30)
            while datetime.now() < end:
                returncode, stdout, stderr = self.send_cmd(cmd)
                if returncode:
                    break
                time.sleep(0.25)
        self.kill_session(session_name)


# use a configurable timeout for hosts if ping succeeded.
class Host(object):
    """Base class for hosts"""

    def __init__(self, hostname, user, port=DEFAULT_PORT):
        self._hostname = hostname
        self._user = user
        self._port = port
        self._ssh_port = DEFAULT_SSH_PORT

    def get_hostname(self):
        return self._hostname

    def get_ssh_port(self):
        return self._ssh_port

    def shutdown(self, timeout=30):
        pass

    def is_up(self):
        cmd = "ping -c 1 {} > /dev/null".format(self._hostname)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        # TODO: check usage of stdout and stderr
        stdout_data, stderr_data = process.communicate()
        return not process.returncode

    def wait_for_host(self, timeout=60):
        logger.info("  waiting for {}...".format(self._hostname))
        end = datetime.now() + timedelta(seconds=timeout)
        while not self.is_up():
            time.sleep(0.25)
            if datetime.now() > end:
                logger.error(
                    "  could not ping '{}' within {} secs".format(
                        self._hostname, timeout
                    )
                )
                return False
        if self._port:
            while True:
                try:
                    socket.create_connection((self._hostname, self._port), timeout=1)
                    break
                except OSError as ex:
                    logger.debug(
                        "  could not connect to '{}:{}' within {} secs: {}".format(
                            self._hostname, self._port, timeout, ex
                        )
                    )
                time.sleep(0.25)
                if datetime.now() > end:
                    logger.error(
                        "  could not connect to '{}:{}' within {} secs".format(
                            self._hostname, self._port, timeout
                        )
                    )
                    return False

        logger.info("  {} is up".format(self._hostname))
        return True


class LinuxHost(Host):
    """Handle linux hosts"""

    def __init__(self, hostname, user, port=DEFAULT_PORT, ssh_port=DEFAULT_SSH_PORT, check_nfs=True):
        super().__init__(hostname, user, port)
        self._ssh_port = ssh_port
        self._ssh_client = SSHClient(user, hostname, ssh_port)
        self._check_nfs = check_nfs

    def shutdown(self, timeout=60):
        logger.info("  shutting down {}...".format(self._hostname))
        cmd = "nohup sh -c '( ( sudo shutdown now -P 0 > /dev/null 2>&1 ) & )'"
        ret, stdout, stderr = self._ssh_client.send_cmd(cmd, get_pty=True)

        if ret == 0:
            end = datetime.now() + timedelta(seconds=timeout)
            while self.is_up():
                time.sleep(0.25)
                if datetime.now() > end:
                    logger.error(
                        "  could not shutdown '{}' within {} secs".format(
                            self._hostname, timeout
                        )
                    )
                    return False
        else:
            logger.error(
                "  could not exec shutdown command on '{}'".format(self._hostname)
            )
            return False

        logger.info("  {} is down".format(self._hostname))
        return True

    def check_nfs_mount(self):
        cmd = "netstat | grep :nfs | grep {}".format(self._hostname)
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        stdout_data, stderr_data = process.communicate()
        return not process.returncode

    def wait_for_host(self, timeout=60):
        end = datetime.now() + timedelta(seconds=timeout)
        if not super().wait_for_host(timeout):
            return False
        logger.info("  waiting for {}, check nfs".format(self._hostname))
        if self._check_nfs:
            while not self.check_nfs_mount():
                time.sleep(0.25)
                if datetime.now() > end:
                    logger.error(
                        "  could not find nfs mount for '{}' within {} secs".format(
                            self._hostname, timeout
                        )
                    )
                    return False

        # Send an initial 'echo' command to verify if sending commands works
        logger.info("  {} sending initial command".format(self._hostname))
        ret = 1
        while ret != 0:
            ret, _, _ = self._ssh_client.send_cmd("echo", get_pty=True)
            if ret != 0:
                logger.error("  {} sending initial command failed".format(self._hostname))
                time.sleep(0.25)
        logger.info("  {} sending initial command succeeded".format(self._hostname))

        return True


# TODO: windows hosts could also use port connection checks instead of simple pings
# if no ports for windows hosts are defined, use ping.
class WindowsHost(Host):
    """Handle windows hosts"""

    def __init__(self, hostname, user, port=DEFAULT_PORT):
        super().__init__(hostname, user, port)

    def shutdown(self, timeout=60):
        logger.info("  shutting down {}...".format(self._hostname))
        cmd = "net rpc shutdown -f -t 1 -I {host} -U rpc_user%rpc_user".format(
            host=self._hostname
        )
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        # TODO: check usage of stdout and stderr
        stdout_data, stderr_data = process.communicate()
        if not process.returncode:
            end = datetime.now() + timedelta(seconds=timeout)
            while self.is_up():
                time.sleep(0.25)
                if datetime.now() > end:
                    logger.error(
                        "  could not shutdown '{}' within {} secs".format(
                            self._hostname, timeout
                        )
                    )
                    return False
        else:
            logger.error(
                "  could not exec shutdown command on '{}'".format(self._hostname)
            )
            return False

        logger.info("  {} is down".format(self._hostname))
        return True


class OnlineHost(Host):
    """Handle hosts which should only be available on the network"""

    def __init__(self, hostname, port=DEFAULT_PORT):
        super().__init__(hostname, "", port)

    def shutdown(self, timeout=60):
        return True


class Session(object):
    def __init__(self, ssh_client, session_name, yaml_session, envs=None) -> None:
        self._session_name = session_name
        self._ssh_client = ssh_client  # type: SSHClient
        self._envs = envs

        if "user" in yaml_session:
            self._user = yaml_session["user"]
        else:
            self._user = DEFAULT_USER

        if "host" in yaml_session:
            self._host = yaml_session["host"]
        else:
            self._host = DEFAULT_HOST

        command_env_prefix = ""
        if self._envs is not None:
            for env in self._envs:
                command_env_prefix += "export {}={} && ".format(env[0], env[1])

        if "command" in yaml_session:
            self._command = command_env_prefix + yaml_session["command"]
        else:
            raise Exception("No command in session section")

        if "wait_for_core" in yaml_session:
            self._wait_for_core = yaml_session["wait_for_core"]
        else:
            self._wait_for_core = True

        if "pre_condition" in yaml_session:
            self._pre_condition = yaml_session["pre_condition"]
        else:
            self._pre_condition = None

        if "prio" in yaml_session:
            self.prio = int(yaml_session["prio"])
        else:
            self.prio = 10

        if "prio_stop" in yaml_session:
            self.prio_stop = int(yaml_session["prio_stop"])
        else:
            self.prio_stop = self.prio

        if "locked" in yaml_session:
            self._locked = yaml_session["locked"]
        else:
            self._locked = False

    # for now it is not possible to detect if a session has started completely
    # (e.g. roslauch command is telling us that all nodes are up) find a way to detect this
    # as ros2 uses python as a launch system, it should be possible to detect this
    def start(self):
        logger.info("  session {}: start".format(self._session_name))

        if self._wait_for_core:
            logger.info("  session {}: waiting for roscore".format(self._session_name))
            # wait for roscore
            while not is_master_online():
                time.sleep(0.25)
                logger.debug(
                    "  session {}: waiting for roscore!".format(self._session_name)
                )
        logger.info("  session {}: roscore online".format(self._session_name))

        if self._pre_condition:
            logger.info(
                "  session {}: checking precondition: {}".format(
                    self._session_name, self._pre_condition
                )
            )
            # check for precondition
            while True:
                ret, stdout, stderr = self._ssh_client.send_cmd(
                    "{}".format(self._pre_condition), True
                )
                logger.debug("pre_condition: {}".format(self._pre_condition))
                logger.debug("ret: {}".format(ret))
                logger.debug("stdout: {}".format(stdout))
                logger.debug("stderr: {}".format(stderr))
                if not ret:
                    break
                time.sleep(0.25)

            logger.info(
                "  session {}: precondition fullfilled: {}".format(
                    self._session_name, self._pre_condition
                )
            )

        if self._ssh_client.has_session(session_name=self._session_name):
            logger.warning("  session {}: already running".format(self._session_name))
        else:
            self._ssh_client.new_session(session_name=self._session_name)
            self._ssh_client.send_keys(self._session_name, self._command)

    def stop(self, force=False):
        logger.info("  session {}: stop".format(self._session_name))
        if self._ssh_client.has_session(session_name=self._session_name):
            if self._locked and not force:
                logger.warning(
                    "  session {}: is locked - skipping...".format(self._session_name)
                )
                return
            self._ssh_client.stop_session(session_name=self._session_name)
        else:
            logger.warning("  session {}: not running".format(self._session_name))

    def restart(self):
        self.stop()
        self.start()

    def terminate(self):
        pass

    def dump(self):
        print("session_name{}:".format(self._session_name))
        print("\thost: {}".format(self._host))
        print("\tuser: {}".format(self._user))
        print("\tcommand: {}".format(self._command))
        print("\tpre_condition: {}".format(self._pre_condition))
        print("\tprio: {}".format(self.prio))
        print("\tprio_stop: {}".format(self.prio_stop))
        print("\tlocked: {}".format(self._locked))


def wait_for_hosts(hosts, timeout=30):
    start = datetime.now()
    logger.info("==================================")
    logger.info("wait for hosts:")

    ret = True

    # remove own host pc from list
    hosts_c = {key: value for key, value in hosts.items() if value.get_hostname() != socket.gethostname()}
    if not hosts_c:
        logger.info("no other hosts specified.")
        return ret

    # concurrently wait for all other hosts
    with ThreadPoolExecutor(max_workers=len(hosts_c)) as executor:
        futures = {
            executor.submit(hosts_c[key].wait_for_host, timeout): key for key in hosts_c
        }

        for f in concurrent.futures.as_completed(futures):
            ret = ret and f.result()

    if ret:
        logger.info("all hosts are up")
    else:
        logger.error("could not reach all hosts")

    logger.debug(
        "waiting for hosts took {} secs".format(
            (datetime.now() - start).total_seconds()
        )
    )
    return ret


def shutdown_system(hosts, timeout=60):
    start = datetime.now()
    logger.info("==================================")
    logger.info("shutting down hosts:")

    # remove own host pc from list
    def is_own_host(host: Host) -> bool:
        if host.get_hostname() in ["localhost", "127.0.0.1", socket.gethostname()]:
            return True
        return False

    hosts_c = {key: value for key, value in hosts.items() if not is_own_host(value)}
    if hosts_c:
        # concurrently shutdown all other hosts
        with ThreadPoolExecutor(max_workers=len(hosts_c)) as executor:
            futures = {
                executor.submit(hosts_c[key].shutdown, timeout): key for key in hosts_c
            }

            for f in concurrent.futures.as_completed(futures):
                f.result()

        logger.debug(
            "shutting down other hosts took {} secs".format((datetime.now() - start).total_seconds())
        )
    else:
        logger.info("no other hosts specified.")

    # shutdown own host
    host = None
    for value in hosts.values():
        if is_own_host(value):
            host = value
    if host:
        host.shutdown(timeout=timeout)
    else:
        logger.error("can not shutdown own system because the hostname {} was not \
            found in the hosts list. Check if your yaml contents are correct.".format(socket.gethostname()))


def order_sessions_by_key(sessions, key):
    ordered_array = sorted(sessions, key=operator.attrgetter(key))
    ordered_sessions = dict()
    for s in ordered_array:
        if not getattr(s, key) in ordered_sessions:
            ordered_sessions[getattr(s, key)] = []
        ordered_sessions[getattr(s, key)].append(s)
    # returns a dict of arrays with prio as key and array of session with the same key(prio) as value
    return ordered_sessions

def start_sessions(sessions):
    start = datetime.now()
    # create thread pool to execute
    for prio in sessions:
        start = datetime.now()
        logger.info("==================================")
        logger.info("start sessions with prio {}:".format(prio))
        with ThreadPoolExecutor(max_workers=len(sessions)) as executor:
            futures = {executor.submit(s.start): s for s in sessions[prio]}
            for f in concurrent.futures.as_completed(futures):
                f.result()
        logger.info(
            "sessions with prio {} started in {} secs".format(
                prio, (datetime.now() - start).seconds
            )
        )
        logger.info("done")
    logger.debug(
        "starting sessions took {} secs".format(
            (datetime.now() - start).total_seconds()
        )
    )


def stop_sessions(sessions, force=False):
    start = datetime.now()
    # create thread pool to execute
    for prio in reversed(sessions):
        start = datetime.now()
        logger.info("==================================")
        logger.info("stop sessions with prio {}:".format(prio))
        with ThreadPoolExecutor(max_workers=len(sessions)) as executor:
            futures = {executor.submit(s.stop, force): s for s in sessions[prio]}
            for f in concurrent.futures.as_completed(futures):
                f.result()
        logger.info(
            "sessions with prio {} stopped in {} secs".format(
                prio, (datetime.now() - start).seconds
            )
        )
        logger.info("done")
    logger.debug(
        "stopping sessions took {} secs".format(
            (datetime.now() - start).total_seconds()
        )
    )

def pre_shutdown_commands(yaml_content, force=False):
    logger.info("execute pre shutdown commands")
    if "pre-shutdown-commands" in yaml_content:
        for cmd in yaml_content["pre-shutdown-commands"]:
            cmd = '/usr/bin/bash -c "'+cmd+'"'
            logger.info("execute command: {}".format(cmd))
            #execute cmd
            process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdio, stderr = process.communicate()
            if process.returncode in [0, 1, 2]:
                logger.info("successfully executed command: {}".format(cmd))
                logger.info("output: {}".format(stdio))
            else:
                logger.error("failed to execute command: {}".format(cmd))
                logger.error("error: {}".format(stderr))
                if not force:
                    sys.exit(1)
    else:
        logger.info("no pre-shutdown-commands defined")

def pre_reboot_commands(yaml_content, force=False):
    logger.info("execute pre reboot commands")
    if "pre-reboot-commands" in yaml_content:
        for cmd in yaml_content["pre-reboot-commands"]:
            cmd = '/usr/bin/bash -c "'+cmd+'"'
            logger.info("execute command: {}".format(cmd))
            #execute cmd
            process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdio, stderr = process.communicate()
            if process.returncode in [0, 1, 2]:
                logger.info("successfully executed command: {}".format(cmd))
                logger.info("output: {}".format(stdio))
            else:
                logger.error("failed to execute command: {}".format(cmd))
                logger.error("error: {}".format(stderr))
                if not force:
                    sys.exit(1)
    else:
        logger.info("no pre-reboot-commands defined")

def validate_yaml_sessions(yaml_sessions):
    #validate session names -> no session name is a prefix of another session name
    session_names = list(yaml_sessions.keys())
    session_names_sorted = sorted(session_names)
    for i in range(1, len(session_names_sorted)):
        if session_names_sorted[i].startswith(session_names_sorted[i-1]):
            logger.error("session names in yaml are not valid")
            logger.error("a session name is not allowed to be a prefix of another session name")
            logger.error("catched sessions: {}, {}".format(session_names_sorted[i-1], session_names_sorted[i]))
            sys.exit(1)

def main():
    start = datetime.now()
    parser = argparse.ArgumentParser(description="robmuxinator")
    parser.add_argument(
        "command",
        choices=["start", "stop", "restart", "shutdown", "reboot"],
        help="which command should be executed",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="the path to the yaml config file",
        default="/etc/ros/upstart_robot.yaml",
    )
    parser.add_argument(
        "-s",
        "--sessions",
        required=False,
        action="append",
        help="which sessions should be started/stopped",
    )
    parser.add_argument(
        "-f",
        "--force",
        required=False,
        action="store_true",
        help="close sessions even if they are locked",
    )
    parser.add_argument(
        "-l",
        "--logging_level",
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="logging level",
    )
    parser.add_argument(
        "--instance_id",
        type=int,
        help="an unique id used to prepend to each session name within the config file. used for multi-robot emulation. the instance_id is also exported to the env used within the sessions as well as to guarantee a unique ROS_DOMAIN_ID",
        default=-1,
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    # parse arguments
    yaml_file = args.config
    command = args.command
    instance_id = args.instance_id

    # set logging level
    logger.setLevel(level=args.logging_level)

    # load yaml file
    with open(yaml_file, "r") as fs:
        yaml_content = yaml.safe_load(fs)

    # check and get hosts
    hosts = dict()
    if "hosts" in yaml_content:
        yaml_hosts = yaml_content["hosts"]
        for key in yaml_hosts:
            if "port" in yaml_hosts[key]:
                port = yaml_hosts[key]["port"]
            else:
                port = DEFAULT_PORT

            if "ssh_port" in yaml_hosts[key]:
                ssh_port = yaml_hosts[key]["ssh_port"]
            else:
                ssh_port = DEFAULT_SSH_PORT

            if "check_nfs" in yaml_hosts[key]:
                check_nfs = yaml_hosts[key]["check_nfs"]
            else:
                check_nfs = True

            if "hostname" in yaml_hosts[key]:
                hostname = yaml_hosts[key]["hostname"]
            else:
                hostname = key

            if yaml_hosts[key]["os"].lower().strip() in ["linux", "windows"]:
                user = yaml_hosts[key]["user"]
                if user.startswith("$"):
                    user = os.getenv(user[1:])
                    if user is None:
                        raise Exception("User variable for host '{}' not set".format(key))

                if yaml_hosts[key]["os"].lower().strip() == "linux":
                    hosts[key] = LinuxHost(
                        hostname, user, port, ssh_port, check_nfs
                    )
                elif yaml_hosts[key]["os"].lower().strip() == "windows":
                    hosts[key] = WindowsHost(hostname, user, port)

            elif yaml_hosts[key]["os"].lower().strip() == "online":
                hosts[key] = OnlineHost(hostname, port)
            else:
                logger.error("unknown host os: {}".format(yaml_hosts[key]["os"]))
                sys.exit(1)

    else:
        logger.error("{} does not contain key 'hosts'".format(yaml_file))
        sys.exit()

    timeout = None
    if "timeout" in yaml_content:
        timeout = yaml_content["timeout"]
    else:
        logger.error("{} does not contain key 'timeout'".format(yaml_file))
        sys.exit()

    # get env_vars from yaml
    if "envs" in yaml_content:
        env_vars = yaml_content["envs"]
        env_vars_filtered = []
        env_values = []
        for env_var in env_vars:
            if os.getenv(env_var) is None:
                raise Exception("mandatory env variable {} is not exported".format(env_var))
            else:
                env_vars_filtered.append(env_var)
                env_values.append(os.getenv(env_var))
        envs = list(zip(env_vars_filtered, env_values))
    else:
        envs = None

    # Check if 'instance_id' was given by the user.
    # This indicates the a multi-instance setup, e.g. for multi-robot emulation.
    # Therefore we export the INSTANCE_ID and use it for to guarantee a unique ROS_DOMAIN_ID
    if instance_id >= 0:
        envs.append(("INSTANCE_ID", instance_id))

    # get sessions from yaml
    yaml_sessions = None
    if "sessions" in yaml_content:
        yaml_sessions = yaml_content["sessions"]
        # validate yaml sessions
        validate_yaml_sessions(yaml_sessions)
    else:
        logger.error("{} does not contain key 'sessions'".format(yaml_file))
        sys.exit()

    # init sessions
    sessions = []
    try:
        for key in yaml_sessions:
            host = DEFAULT_HOST
            user = DEFAULT_USER
            if "host" in yaml_sessions[key]:
                host = yaml_sessions[key]["host"]

            if "user" in yaml_sessions[key]:
                user = yaml_sessions[key]["user"]
                if user.startswith("$"):
                    user = os.getenv(user[1:])
                    if user is None:
                        raise Exception("User variable for session '{}' not set".format(key))

            if args.sessions:
                if key in args.sessions:
                    sessions.append(
                        Session(
                            SSHClient(user=user, hostname=hosts[host].get_hostname(), port=hosts[host].get_ssh_port()),
                            str(instance_id) + "_" + key if instance_id > 0 else key,
                            yaml_sessions[key],
                            envs
                        )
                    )
            else:
                sessions.append(
                    Session(
                        SSHClient(user=user, hostname=hosts[host].get_hostname(), port=hosts[host].get_ssh_port()),
                        str(instance_id) + "_" + key if instance_id > 0 else key,
                        yaml_sessions[key],
                        envs
                    )
                )
    except Exception as e:
        logger.error(e)
        sys.exit()

    ordered_sessions_start = order_sessions_by_key(sessions, "prio")
    ordered_sessions_stop = order_sessions_by_key(sessions, "prio_stop")

    if command == "start":
        # wait for other hosts
        if len(hosts) > 1 and not wait_for_hosts(hosts, timeout):
            sys.exit()
        start_sessions(ordered_sessions_start)
        logger.info(
            "starting took {} secs".format((datetime.now() - start).total_seconds())
        )
    elif command == "stop":
        stop_sessions(ordered_sessions_stop, args.force)
        logger.info(
            "stopping took {} secs".format((datetime.now() - start).total_seconds())
        )
    elif command == "restart":
        stop_sessions(ordered_sessions_stop, args.force)
        start_sessions(ordered_sessions_start)
        logger.info(
            "restart took {} secs".format((datetime.now() - start).total_seconds())
        )
    elif command == "shutdown":
        pre_shutdown_commands(yaml_content, args.force)
        stop_sessions(ordered_sessions_stop, True)
        shutdown_system(hosts, timeout)
    elif command == "reboot":
        pre_reboot_commands(yaml_content, args.force)
        pre_shutdown_commands(yaml_content, args.force)
        stop_sessions(ordered_sessions_stop, True)
        shutdown_system(hosts, timeout)
