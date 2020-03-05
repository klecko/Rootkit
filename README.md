# Rootkit
Let's try to create a rootkit!

## Features
- Hide files by name
- Hide files whose name contains a magic string
- Hide processes by PID
- Hide the rootkit itself
- See hidden files and PIDs
- Backdoor thread to provide reverse shell as root

## Tested on
- **Ubuntu 18.04.3**: 5.4.8-050408-generic, 5.0.0-37-generic, 4.17.0-041700-generic, 4.15.0-72-generic

## Details
The rootkit hooks system calls overwriting the syscall table. This allows changing their behavior, causing getdents not to list a hidden file or a hidden entry in `/proc`, or causing kill to return 'process not found' when it's called on a hidden process, among others. In order to get as much consistency as possible, every syscall with a `pid_t` argument is hooked (if any is missing, will be added soon).

To communicate with the rootkit from userland, it creates a virtual proc file where it reads requests. A simple client is provided in [client.c](../master/src/client.c)

There's a [config file](../master/src/config.h) where you can enable or disable the backdoor thread, hooks, set the magic string and the proc filename, etc.

Also, a sample [backdoor script](../master/backdoor.sh) and [web server](../master/server.py) are included. The web server is made with Flask, it lists every active rootkit and provides a button to ask for a reverse shell. Just run `nc -lvp PORT`, click the button, and enjoy!
The backdoor thread of the rootkit runs the backdoor script every few seconds, which updates the web server and grants a reverse shell if requested.

![web](https://i.imgur.com/7ZY1tDC.png "Web server")

## Sample usage
- Set the IPs and ports in the server and in the backdoor script.
- Build and install in the victim: `./build.sh`. This will copy the backdoor script to `/tmp`, build the client and the rootkit and run `insmod` on it.
- Hide files and PIDs with `./client`.
- Run the web server: `python3 server.py`. You may need to install Flask before: `pip install flask`.
- The web server should now have an entry with the data of the victim.
- Run `nc -lvp PORT`, with `PORT` being the `SHELL_PORT` variable set in the server.
- Click the "Get Shell" button, wait a few secs.
- Enjoy the shell!
