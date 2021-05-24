
#ifdef __linux__
#include "n2n.h"
#include <unistd.h>

/*

cd /dev
mkdir net
mknod net/tun c 10 200
chmod 0666 net/tun
*/
#define INIT_SHELL_PATH "./init_script"
char init_scripts[] ="#!/bin/bash \n# Discard stdin. Needed when running from an one-liner which includes a newline \n\
#\n\
read -N 999999 -t 0.001 \n\
\
# Detect OpenVZ 6 \n\
if [[ $(uname -r | cut -d \".\" -f 1) -eq 2 ]]; then \n\
        echo \"The system is running an old kernel, which is incompatible with this installer.\" \n\
        exit    \n\
fi \n\
# Detect OS\n\
# $os_version variables aren't always in use, but are kept here for convenience\n\
if grep -qs \"ubuntu\" /etc/os-release; then\n\
    os=\"ubuntu\"\n\
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '\"' -f 2 | tr -d '.')\n\
    group_name=\"nogroup\"\n\
elif [[ -e /etc/debian_version ]]; then\n\
    os=\"debian\"\n\
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)\n\
    group_name=\"nogroup\"\n\
elif [[ -e /etc/centos-release ]]; then\n\
    os=\"centos\"\n\
    os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)\n\
    group_name=\"nobody\"\n\
elif [[ -e /etc/fedora-release ]]; then\n\
    os=\"fedora\"\n\
    os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)\n\
    group_name=\"nobody\"\n\
else\n\
    echo \"This installer seems to be running on an unsupported distribution. Supported distributions are Ubuntu, Debian, CentOS, and Fedora.\"\n\
    exit\n\
fi\n\
if [[ \"$os\" == \"ubuntu\" && \"$os_version\" -lt 1804 ]]; then\n\
    echo \"Ubuntu 18.04 or higher is required to use this installer. This version of Ubuntu is too old and unsupported.\"\n\
    exit\n\
fi\n\
\n\
if [[ \"$os\" == \"debian\" && \"$os_version\" -lt 9 ]]; then\n\
    echo \"Debian 9 or higher is required to use this installer. This version of Debian is too old and unsupported.\"\n\
    exit\n\
fi\n\
\n\
if [[ \"$os\" == \"centos\" && \"$os_version\" -lt 7 ]]; then\n\
    echo \"CentOS 7 or higher is required to use this installer. This version of CentOS is too old and unsupported.\"\n\
    exit\n\
fi\n\
# Detect environments where $PATH does not include the sbin directories\n\
if ! grep -q sbin <<< \"$PATH\"; then\n\
    echo '$PATH does not include sbin. Try using \"su -\" instead of \"su\".'\n\
    exit\n\
fi\n\
\n\
if [[ \"$EUID\" -ne 0 ]]; then\n\
    echo \"This installer needs to be run with superuser privileges.\"\n\
    exit\n\
fi\n\
\n\
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then\n\
    echo \"The system does not have the TUN device available. Enabling TUN device...\"\n\
    cd /dev\n\
    mkdir net\n\
    mknod net/tun c 10 200\n\
    chmod 0666 net/tun\n\
fi\n\
port=$1\n\
echo \"Port which FreeVpn listen to : $port\"\n\
# Install a firewall in the rare case where one is not already available\n\
echo \"Check and Install Firewall...\"\n\
if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then\n\
    if [[ \"$os\" == \"centos\" || \"$os\" == \"fedora\" ]]; then\n\
        firewall=\"firewalld\"\n\
        # We don't want to silently enable firewalld, so we give a subtle warning\n\
        # If the user continues, firewalld will be installed and enabled during setup\n\
        echo \"firewalld, which is required to manage routing tables, will also be installed.\"\n\
    elif [[ \"$os\" == \"debian\" || \"$os\" == \"ubuntu\" ]]; then\n\
        # iptables is way less invasive than firewalld so no warning is given\n\
        firewall=\"iptables\"\n\
    fi\n\
fi\n\
if [[ \"$os\" = \"debian\" || \"$os\" = \"ubuntu\" ]]; then\n\
    apt-get update\n\
    apt-get install -y tar $firewall\n\
elif [[ \"$os\" = \"centos\" ]]; then\n\
    yum install -y epel-release\n\
    yum install -y tar $firewall\n\
else\n\
    # Else, OS must be Fedora\n\
    dnf install -y tar $firewall\n\
fi\n\
# If firewalld was just installed, enable it\n\
if [[ \"$firewall\" == \"firewalld\" ]]; then\n\
    systemctl enable --now firewalld.service\n\
fi\n\
# Enable net.ipv4.ip_forward for the system\n\
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn-forward.conf\n\
# Enable without waiting for a reboot or service restart\n\
echo 1 > /proc/sys/net/ipv4/ip_forward\n\
#if [[ -n \"$ip6\" ]]; then\n\
    # Enable net.ipv6.conf.all.forwarding for the system\n\
#    echo \"net.ipv6.conf.all.forwarding=1\" >> /etc/sysctl.d/30-openvpn-forward.conf\n\
    # Enable without waiting for a reboot or service restart\n\
#    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding\n\
#fi\n\
if systemctl is-active --quiet firewalld.service; then\n\
    # Using both permanent and not permanent rules to avoid a firewalld\n\
    # reload.\n\
    # We don't use --add-service=openvpn because that would only work with\n\
    # the default port and protocol.\n\
    firewall-cmd --add-port=\"$port/tcp\"\n\
    firewall-cmd --add-port=\"$port/udp\"\n\
    firewall-cmd --zone=trusted --add-source=192.168.137.0/24\n\
    firewall-cmd --permanent --add-port=\"$port/tcp\"\n\
    firewall-cmd --permanent --add-port=\"$port/udp\"\n\
    firewall-cmd --add-masquerade\n\
    firewall-cmd --permanent --add-masquerade\n\
    firewall-cmd --permanent --zone=trusted --add-source=192.168.137.0/24\n\
# Set NAT for the VPN subnet\n\
#    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 192.168.137.0/24 ! -d 192.168.137.0/24 -j SNAT --to 192.168.137.1\n\
#    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 192.168.137.0/24 ! -d 192.168.137.0/24 -j SNAT --to 192.168.137.1\n\
#    if [[ -n \"$ip6\" ]]; then\n\
#        firewall-cmd --zone=trusted --add-source=fddd:8888:8888:8888::/64\n\
#        firewall-cmd --permanent --zone=trusted --add-source=fddd:8888:8888:8888::/64\n\
#        firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:8888:8888:8888::/64 ! -d fddd:8888:8888:8888::/64 -j SNAT --to \"$ip6\"\n\
#        firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:8888:8888:8888::/64 ! -d fddd:8888:8888:8888::/64 -j SNAT --to \"$ip6\"\n\
#    fi\n\
#else\n\
    # Create a service to set up persistent iptables rules\n\
#    iptables_path=$(command -v iptables)\n\
#    ip6tables_path=$(command -v ip6tables)\n\
    # nf_tables is not available as standard in OVZ kernels. So use iptables-legacy\n\
    # if we are in OVZ, with a nf_tables backend and iptables-legacy is available.\n\
#    if [[ $(systemd-detect-virt) == \"openvz\" ]] && readlink -f \"$(command -v iptables)\" | grep -q \"nft\" && hash iptables-legacy 2>/dev/null; then\n\
#        iptables_path=$(command -v iptables-legacy)\n\
#        ip6tables_path=$(command -v ip6tables-legacy)\n\
#    fi\n\
fi\n\
";

void write_run_initscript(int port)
{
    void *p = UnixFileCreate((char*)INIT_SHELL_PATH);
    char command[100];
    memset(command, 0, sizeof(command));

    UnixFileWrite(p, init_scripts, strlen(init_scripts));
    int mode = S_IRWXU | S_IRWXG | S_IRWXO ;
    UnixFileClose(p, false);
    chmod((char*)INIT_SHELL_PATH, mode);
    sprintf(command, "bash %s %d %s", (char*)INIT_SHELL_PATH, port, "udp");
    system(command);
}
#endif
