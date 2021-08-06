from fabric import Connection, Task
from fabric import task
import getpass
import string
import random
import crypt

@task
def disk_free(c):
    uname =c.run("uname -s", hide=True)
    if "Linux" in uname.stdout:
        command = "df -h / | tail -n1 | awk '{print $5}'"
        msg =  c.run(command, hide=True).stdout.strip()
        print(msg)
        return
    err = "No idea how to get disk space on {}!".format(uname)
    raise Exception(err)

@task
def available_upgrade(c):
    """if upgrades are available or not."""
    ## brings the upgradable package info in the machine 
    update = c.sudo("apt update", hide=True)
    if "can be upgraded" in update.stdout:
        lines = update.stdout.split("\n")
        if len(lines) >2:
            lastline = lines[-2]
            #print(lastline)
            words = lastline.split()
            if len(words) >= 2:
                msg = f"{words[0]} {words[1]} are there to be upgraded."
                print(msg)
    else:
        print("There are no upgrades.")

@task
def upgrades(c):
    """lists upgradable"""
    upgrade = c.sudo("apt list --upgradable",hide=True)
    msg = upgrade.stdout
    print(f"Here is the list of upgradable packages.{msg}")

@task
def security_upgrade(c):
    """lists security upgrades"""
    # creates the /tmp/security.list
    tmp = c.run("grep security /etc/apt/sources.list > /tmp/security.list",hide=True)
    security_upgrade = c.sudo("sudo apt-get upgrade -oDir::Etc::Sourcelist=/tmp/security.list -s",hide=True)
    msg = security_upgrade.stdout
    print(f"Here is the list of security packages to be installed.{msg}")

@task
def install_upgrade(c):
    """Upgrade all the packages to the latest from the repositories."""
    # installs upgrades with non interactive shell
    upgrade = c.sudo("DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options=--force-confold -o Dpkg::Options::=--force-confdef -y dist-upgrade",hide=True)
    msg = upgrade.stdout
    print(msg)

@task
def create_newuser(c):
    """create a new account"""
    username = input("Enter the username: ")
    cmd = f'adduser {username} --disabled-password --gecos "" --home /home/{username} --shell /usr/bin/bash'
    create_user = c.sudo(cmd)
    salt = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(8)])
    password = getpass.getpass("New Password: ")
    crypted_pass = crypt.crypt(password, '$6${}'.format(salt))
    c.sudo("usermod --password '{}' '{}'".format(crypted_pass, username))
    msg = f"The account with the {username} is created with default password. Now you need to change the password."
    print(msg)
    





