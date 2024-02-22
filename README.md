# robmuxinator

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The `robmuxinator` script serves as a command-line tool to manage and control `tmux` sessions on multiple hosts of your robot. If you use [`tmux`](github.com/tmux/tmux) you will love `robmuxinator`! It is designed to simplify the execution of various commands. You can for example launch processes of your ROS bringup and application or run a Docker container with it.

It is also helpful for local development to start multiple commands easily with one command.

- [robmuxinator](#robmuxinator)
  - [Installation](#installation)
  - [Getting Started](#getting-started)
  - [Usage](#usage)
    - [Command Choices](#command-choices)
    - [Command-Line Arguments](#command-line-arguments)
    - [YAML Configuration](#yaml-configuration)
  - [tmux commands](#tmux-commands)
    - [Basic Commands](#basic-commands)
    - [Session Management](#session-management)
    - [Windows](#windows)
    - [Copy Mode (Scrolling)](#copy-mode-scrolling)
  - [License](#license)

## Installation

Install the robmuxinator with one simple command
```
sudo pip install .
```

After that, you have to ensure that the root user has SSH access to every user which is used by `robmuxinator`. Simply copy your SSH credentials to the user by `ssh-copy-id username@hostname`

### Nix

`robmuxinator` is also a [Nix Flake](https://nixos.wiki/wiki/Flakes) and available as package under `github:mojin-robotics/robmuxinator#robmuxinator`.

## Getting Started

Execute the steps from [Prerequisites](#prerequisites).

*Local Development*

To get started locally with `robmuxinator`, this would be a `robot.yaml` for local development.

```yaml
timeout: 120

hosts:
  localhost:
    user: $USER

sessions:
  roscore:
    user: $USER
    host: localhost
    prio: 0
    command: roscore
    wait_for_core: false
  bringup:
    user: $USER
    host: localhost
    prio: 1
    command: echo 'starting bringup...'
  
```

To start the `tmux` sessions use `robmuxinator -c ~/path-to-file start`. Now, you are able to see your sessions with `tmux ls`
and you can attach to them with all your favorite `tmux` commands. For reference see this [cheatsheet](#tmux-commands).

*Remote Hosts*

For remote hosts the following YAML config can be used. This starts two sessions on host 1 (`h1`) and host 2 `h2`.
The `port` is used to check wether the host is ready to receive commands.

```yaml
timeout: 120

hosts:
  h1:
    user: robot
    port: 22
  h2:
    user: robot
    port: 22

sessions:
  roscore:
    user: robot
    host: h1
    prio: 0
    command: roscore
    wait_for_core: false
  bringup:
    user: robot
    host: h2
    prio: 1
    command: echo 'starting bringup...'
  
```
## Usage
### Command Choices

- `start`: Start specified sessions on all hosts.
- `stop`: Stop specified sessions on all hosts.
- `restart`: Restart specified sessions on all hosts.
- `shutdown`: Execute shutdown procedures on all hosts.
- `reboot`: Execute reboot procedures on all hosts.

### Command-Line Arguments

- `command`: Choose one of the available commands (start, stop, restart, shutdown, reboot).
- `-c` or `--config`: Specify the path to the YAML configuration file that defines the hosts, sessions, and other settings. The default configuration file path is "/etc/ros/cob.yaml."
- `-s` or `--sessions`: Optionally, specify which sessions should be started or stopped. You can provide multiple session names as arguments.
- `-f` or `--force`: Use this flag to force the closure of sessions, even if they are locked.

### YAML Configuration

- The script relies on a YAML configuration file to define hosts, sessions, and other parameters. The YAML file should include information about the hosts, their operating systems (Linux, Windows, online), session details, and more.


*Global Options*

- `timeout: int` (mandatory): Seconds to wait for a host on startup.

*Hosts of Robot*

- `os: string` {linux, windows, online} (mandatory): Operating system of the host. Hosts of type `online` will only be checked for network availability.
- `user: string` (optional, default: robot): User on the host machine used for sending SSH commands.
- `port: int` (optional, default: none): The port that is checked to determine if a service on the host is already up.
- `hostname: string` (optional, default: `<key>` of `hosts` section): The hostname of the host PC.
- `check_nfs: bool` (optional, default: true): Whether the host should be checked for NFS status. Only supported on Linux.

*Sessions of the Hosts*

- `command: string` (mandatory): Bash command executed in the `tmux` session. A session without the `command` key will result in an exception.
- `host: string` (optional, default: hostname of localhost): Target host of the `tmux` session.
- `user: string` (optional, default: robot): Target user of the `tmux` session.
- `wait_for_core: bool` (optional, default: true): Starts the session only after `roscore` is available.
- `prio: int` (optional, default: 10): Priority of the session. Sessions with the same priority start concurrently. Smaller numbers have higher priority.
- `locked: bool` (optional, default: false): Locked sessions won't be closed on `stop` or `restart` (only if forced).
- `pre_condition: string` (optional): Bash command used as a condition that must be fulfilled before the session can start.


## tmux commands

This is s summary of useful commands for working with `tmux`.

### Basic Commands

- **Start a New Session:** `tmux`
- **Detach from Session:** `Ctrl-b d`
- **Attach to a Session:** `tmux attach-session -t session_name`

### Session Management

- **Create a Named Session:** `tmux new-session -s session_name`
- **List Sessions:** `tmux list-sessions`
- **Switch to Another Session:** `tmux switch-client -t session_name`
- **Kill a Session:** `tmux kill-session -t session_name`

### Windows

- **List Windows:** `Ctrl-b w`
- **Switch to Next Window:** `Ctrl-b n`
- **Switch to Previous Window:** `Ctrl-b p`

### Copy Mode (Scrolling)

- **Enter Copy Mode:** `Ctrl-b [`
- **Exit Copy Mode:** `q`
- **Scroll Up:** `Ctrl-b [`, then use arrow keys or Page Up/Down
- **Search Forward:** `Ctrl-b [`, then `/`, type search text, and press Enter
- **Search Backward:** `Ctrl-b [`, then `?`, type search text, and press Enter


## License
Apache License Version 2.0, January 2004

