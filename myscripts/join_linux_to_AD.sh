#!/bin/sh
DIRECTORY_ID=""
REALM=""
LINUX_DISTRO=""
CURTIME=$(date | sed 's/ //g')
REGION=""
# https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html
AWSCLI="/usr/local/bin/aws"
# script arguments 
DOMAIN_USERNAME=$1
DOMAIN_PASSWORD=$2
DIRECTORY_NAME=$3
DNS_IP_ADDRESS1=$4
DNS_IP_ADDRESS2=$5
COMPUTER_NAME=$6
DIRECTORY_OU=$7

##################################################
## Set hostname to NETBIOS computer name #########
##################################################
set_hostname() {
    INSTANCE_NAME=$(hostname --short) 2>/dev/null

    # NetBIOS computer names consist of up to 15 bytes of OEM characters
    # https://docs.microsoft.com/en-us/windows/win32/sysinfo/computer-names?redirectedfrom=MSDN

    # Naming conventions in Active Directory
    # https://support.microsoft.com/en-us/help/909264/naming-conventions-in-active-directory-for-computers-domains-sites-and
    #RANDOM_COMPUTER_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)
    #COMPUTER_NAME=$(echo EC2AMAZ-$RANDOM_COMPUTER_NAME)
    HOSTNAMECTL=$(which hostnamectl 2>/dev/null)
    if [ ! -z "$HOSTNAMECTL" ]; then
        sudo hostnamectl set-hostname $COMPUTER_NAME.$DIRECTORY_NAME >/dev/null
    else
        sudo hostname $COMPUTER_NAME.$DIRECTORY_NAME >/dev/null
    fi
    if [ $? -ne 0 ]; then echo "***Failed: set_hostname(): set hostname failed" && exit 1; fi

    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-hostname.html
    if [ -f /etc/sysconfig/network ]; then
            sudo sed -i "s/HOSTNAME=.*$//g" /etc/sysconfig/network
        sudo echo "HOSTNAME=$COMPUTER_NAME.$DIRECTORY_NAME" > /tmp/sysconfig_temp
		sudo cp -f /tmp/sysconfig_temp /etc/sysconfig/network
    fi
}

##################################################
## Get Region from Instance Metadata #############
##################################################
get_region() {
    REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null | grep region | awk -F: '{ print $2 }' | tr -d '\", ')
}

##################################################
########## Install components ####################
##################################################
install_components() {
    LINUX_DISTRO=$(sudo cat /etc/os-release | grep NAME | awk -F'=' '{print $2}')
    LINUX_DISTRO_VERSION_ID=$(sudo cat /etc/os-release | grep VERSION_ID | awk -F'=' '{print $2}' | tr -d '"')
    if [ -z $LINUX_DISTRO_VERSION_ID ]; then
       echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
       exit 1
    fi

    if grep 'CentOS' /etc/os-release 1>/dev/null 2>/dev/null; then
        if [ "$LINUX_DISTRO_VERSION_ID" -lt "7" ] ; then
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
        fi
        LINUX_DISTRO='CentOS'
        # yum -y update
        ## yum update takes too long
        sudo yum -y install realmd adcli oddjob-mkhomedir oddjob samba-winbind-clients samba-winbind samba-common-tools samba-winbind-krb5-locator krb5-workstation unzip >/dev/null
        if [ $? -ne 0 ]; then echo "install_components(): yum install errors for CentOS" && return 1; fi
    elif grep -e 'Red Hat' /etc/os-release 1>/dev/null 2>/dev/null; then
        LINUX_DISTRO='RHEL'
        RHEL_MAJOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $1}')
        RHEL_MINOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $2}')
        if [ $RHEL_MAJOR_VERSION -eq "7" ] && [ ! -z $RHEL_MINOR_VERSION ] && [ $RHEL_MINOR_VERSION -lt "6" ]; then
            # RHEL 7.5 and below are not supported
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
        fi
        if [ $RHEL_MAJOR_VERSION -eq "7" ] && [ -z $RHEL_MINOR_VERSION ]; then
            # RHEL 7 is not supported
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
        fi
        # yum -y update
        ## yum update takes too long
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/deploying_different_types_of_servers/index
        sudo yum -y  install realmd adcli oddjob-mkhomedir oddjob samba-winbind-clients samba-winbind samba-common-tools samba-winbind-krb5-locator krb5-workstation python3 vim unzip >/dev/null
        sudo alias python=python3
        if [ $? -ne 0 ]; then echo "install_components(): yum install errors for Red Hat" && return 1; fi
        sudo systemctl restart dbus 2>/dev/null
    elif grep -e 'Fedora' /etc/os-release 1>/dev/null 2>/dev/null; then
        LINUX_DISTRO='Fedora'
        ## yum update takes too long, but it is unavoidable here.
        sudo yum -y update
        sudo yum -y  install realmd adcli oddjob-mkhomedir oddjob samba-winbind-clients samba-winbind samba-common-tools samba-winbind-krb5-locator krb5-workstation python3 vim unzip >/dev/null
        sudo alias python=python3
        if [ $? -ne 0 ]; then echo "install_components(): yum install errors for Fedora" && return 1; fi
        sudo systemctl restart dbus 2>/dev/null
    elif grep 'Amazon Linux' /etc/os-release 1>/dev/null 2>/dev/null; then
         LINUX_DISTRO='AMAZON_LINUX'
         # yum -y update
         ## yum update takes too long
         sudo yum -y  install realmd adcli oddjob-mkhomedir oddjob samba-winbind-clients samba-winbind samba-common-tools samba-winbind-krb5-locator krb5-workstation unzip  >/dev/null
         if [ $? -ne 0 ]; then echo "install_components(): yum install errors for Amazon Linux" && return 1; fi
    elif grep 'Ubuntu' /etc/os-release 1>/dev/null 2>/dev/null; then
         LINUX_DISTRO='UBUNTU'
         UBUNTU_MAJOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $1}')
         UBUNTU_MINOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $2}')
         if [ $UBUNTU_MAJOR_VERSION -lt "14" ]; then
            # Ubuntu versions below 14.04 are not supported
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
         fi
         # set DEBIAN_FRONTEND variable to noninteractive to skip any interactive post-install configuration steps.
         sudo export DEBIAN_FRONTEND=noninteractive
         sudo apt-get -y update
         if [ $? -ne 0 ]; then echo "install_components(): apt-get update errors for Ubuntu" && return 1; fi
         sudo apt-get -yq install realmd adcli winbind samba libnss-winbind libpam-winbind libpam-krb5 krb5-config krb5-locales krb5-user packagekit  ntp unzip python > /dev/null
         if [ $? -ne 0 ]; then echo "install_components(): apt-get install errors for Ubuntu" && return 1; fi
         # Disable Reverse DNS resolution. Ubuntu Instances must be reverse-resolvable in DNS before the realm will work.
         sudo sed -i "s/default_realm.*$/default_realm = $REALM\n\trdns = false/g" /etc/krb5.conf
         if [ $? -ne 0 ]; then echo "install_components(): access errors to /etc/krb5.conf"; return 1; fi
         if ! grep "Ubuntu 16.04" /etc/os-release 2>/dev/null; then
             pam-auth-update --enable mkhomedir
         fi
    elif grep 'SUSE Linux' /etc/os-release 1>/dev/null 2>/dev/null; then
         SUSE_MAJOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $1}')
         SUSE_MINOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $2}')
         if [ "$SUSE_MAJOR_VERSION" -lt "15" ]; then
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
         fi
         if [ "$SUSE_MAJOR_VERSION" -eq "15" ]; then
            sudo SUSEConnect -p PackageHub/15.1/x86_64
         fi
         LINUX_DISTRO='SUSE'
         sudo zypper update -y
         sudo zypper -n install realmd adcli sssd sssd-tools sssd-ad samba-client krb5-client samba-winbind krb5-client python
         if [ $? -ne 0 ]; then
            return 1
         fi
         alias python=python3
    elif grep 'Debian' /etc/os-release; then
         DEBIAN_MAJOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $1}')
         DEBIAN_MINOR_VERSION=$(echo $LINUX_DISTRO_VERSION_ID | awk -F'.' '{print $2}')
         if [ "$DEBIAN_MAJOR_VERSION" -lt "9" ]; then
            echo "**Failed : Unsupported OS version $LINUX_DISTRO : $LINUX_DISTRO_VERSION_ID"
            exit 1
         fi
         sudo apt-get -y update
         LINUX_DISTRO='DEBIAN'
         DEBIAN_FRONTEND=noninteractive apt-get -yq install realmd adcli winbind samba libnss-winbind libpam-winbind libpam-krb5 krb5-config krb5-locales krb5-user packagekit  ntp unzip > /dev/null
         if [ $? -ne 0 ]; then
            return 1
         fi
    fi

    if uname -a | grep -e "x86_64" -e "amd64"; then
        sudo curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
        if [ $? -ne 0 ]; then
                sudo curl -1 "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
                if [ $? -ne 0 ]; then
                    echo "***Failed: install_components curl -1 https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip failed." && exit 1
                fi
        fi
    elif uname -a | grep "aarch64"; then
        sudo curl "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "/tmp/awscliv2.zip"
        if [ $? -ne 0 ]; then
                sudo curl -1 "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o "/tmp/awscliv2.zip"
                if [ $? -ne 0 ]; then
                    echo "***Failed: install_components curl -1 https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip failed." && exit 1
                fi
        fi
    else
        echo "***Failed: install_components processor type is unsupported." && exit 1
    fi

    cd /tmp
    unzip -o awscliv2.zip 1>/dev/null
    sudo ./aws/install -u 1>/dev/null
    if [ $? -ne 0 ]; then echo "***Failed: aws cli install" && exit 1; fi
    cd -
    return 0
}

setup_resolv_conf_and_dhclient_conf() {
    if [ ! -z "$DNS_IP_ADDRESS1" ] && [ ! -z "$DNS_IP_ADDRESS2" ]; then
        sudo mv /etc/resolv.conf /etc/resolv.conf.backup."$CURTIME"
		#sudo touch /etc/resolv.conf
        sudo echo "search $DIRECTORY_NAME" > /tmp/resolv.conf
        sudo echo "nameserver $DNS_IP_ADDRESS1" >> /tmp/resolv.conf
        sudo echo "nameserver $DNS_IP_ADDRESS2" >> /tmp/resolv.conf
		sudo cp -f /tmp/resolv.conf /etc/resolv.conf
        #sudo touch /etc/dhcp/dhclient.conf
        sudo mv /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.backup."$CURTIME"
        sudo echo "supersede domain-name-servers $DNS_IP_ADDRESS1, $DNS_IP_ADDRESS2;" > /tmp/dhclient.conf
		sudo cp -f /tmp/dhclient.conf /etc/dhcp/dhclient.conf
    elif [ ! -z "$DNS_IP_ADDRESS1" ] && [ -z "$DNS_IP_ADDRESS2" ]; then
        sudo touch /etc/resolv.conf
        sudo mv /etc/resolv.conf /etc/resolv.conf.backup."$CURTIME"
        sudo echo "search $DIRECTORY_NAME" > /tmp/resolv.conf
        sudo echo "nameserver $DNS_IP_ADDRESS1" >> /tmp/resolv.conf
		sudo cp -f /tmp/resolv.conf /etc/resolv.conf
        sudo mv /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.backup."$CURTIME"
        sudo echo "supersede domain-name-servers $DNS_IP_ADDRESS1;" > /tmp/dhclient.conf
		sudo cp -f /tmp/dhclient.conf /etc/dhcp/dhclient.conf
    elif [ -z "$DNS_IP_ADDRESS1" ] && [ ! -z "$DNS_IP_ADDRESS2" ]; then
        sudo touch /etc/resolv.conf
        sudo mv /etc/resolv.conf /etc/resolv.conf.backup."$CURTIME"
        sudo echo "search $DIRECTORY_NAME" > /tmp/resolv.conf
        sudo echo "nameserver $DNS_IP_ADDRESS2" >> /tmp/resolv.conf
		sudo cp -f /tmp/resolv.conf /etc/resolv.conf
        sudo mv /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.backup."$CURTIME"
        sudo echo "supersede domain-name-servers $DNS_IP_ADDRESS2;" > /tmp/dhclient.conf
		sudo cp -f /tmp/dhclient.conf /etc/dhcp/dhclient.conf
    else
        echo "***Failed: No DNS IPs available" && exit 1
    fi
}

##################################################
## Set PEER_DNS to yes ###########################
##################################################
set_peer_dns() {
    for f in $(ls /etc/sysconfig/network-scripts/ifcfg-*)
    do
        if echo $f | grep "lo"; then
            continue
        fi
        if ! grep PEERDNS $f; then
            echo "" >> $f
            echo PEERDNS=yes >> $f
        fi
    done
}

##################################################
## Print shell variables #########################
##################################################
print_vars() {
    #echo "REGION = $REGION"
    #echo "DIRECTORY_ID = $DIRECTORY_ID"
    echo "DIRECTORY_NAME = $DIRECTORY_NAME"
    #echo "DIRECTORY_OU = $DIRECTORY_OU"
    #echo "REALM = $REALM"
    echo "COMPUTER_NAME = $COMPUTER_NAME"
    echo "hostname = $(hostname)"
    echo "LINUX_DISTRO = $LINUX_DISTRO"
}

#########################################################
## Add FQDN and Hostname to Hosts file for below error ##
# No DNS domain configured for ip-172-31-12-23.         #
# Unable to perform DNS Update.                         #
#########################################################
configure_hosts_file() {
    fullhost="${COMPUTER_NAME}.${DIRECTORY_NAME}"  # ,, means lowercase since bash v4
    ip_address="$(sudo ip -o -4 addr show eth0 | awk '{print $4}' | cut -d/ -f1)"
    cleanup_comment=''
    sudo sed -i".orig" -r\
        "/^.*${cleanup_comment}/d;\
        /^127.0.0.1\s+localhost\s*/a\\${ip_address} ${fullhost} ${COMPUTER_NAME} ${cleanup_comment}" /etc/hosts
}

##################################################
## Add AWS Directory Service DNS IP Addresses as #
## primary to the resolv.conf and dhclient       #
## configuration files.                          #
##################################################
do_dns_config() {
    setup_resolv_conf_and_dhclient_conf
    if [ $LINUX_DISTRO = 'AMAZON_LINUX' ]; then
        set_peer_dns
    fi

    if [ $LINUX_DISTRO = "UBUNTU" ]; then
        if [ -d /etc/netplan ]; then
            # Ubuntu 18.04
            sudo cat << EOF | tee /etc/netplan/99-custom-dns.yaml
network:
    version: 2
    ethernets:
        eth0:
            nameservers:
                addresses: [$DNS_IP_ADDRESS1, $DNS_IP_ADDRESS2]
            dhcp4-overrides:
                use-dns: false
EOF
            sudo netplan apply
            if [ $? -ne 0 ]; then echo "***Failed: do_dns_config(): netplan apply failed" && exit 1; fi
            # Seems to fail otherwise
            sleep 15
        fi
    fi

    if [ $LINUX_DISTRO = "RHEL" ] || [ $LINUX_DISTRO = "Fedora" ]; then
        set_peer_dns
        if [ -f /etc/NetworkManager/NetworkManager.conf ]; then
            sudo cp /etc/NetworkManager/NetworkManager.conf /etc/NetworkManager/NetworkManager.conf."$CURTIME"
            sudo cat /etc/NetworkManager/NetworkManager.conf."$CURTIME" | sed "s/\[main\]/[main]\ndns=none/g" > /etc/NetworkManager/NetworkManager.conf
        fi
    fi

    if [ $LINUX_DISTRO = "CentOS" ]; then
        set_peer_dns
    fi
}


##################################################
## DNS may already be reachable if DHCP option  ##
## sets are used.                               ##
##################################################
is_directory_reachable() {
    MAX_RETRIES=5
    for i in $(seq 1 $MAX_RETRIES)
    do
        ping -c 1 "$DIRECTORY_NAME" 2>/dev/null
        if [ $? -eq 0 ]; then
            return 0
        fi
    done

    return 1
}

##################################################
## Join Linux instance to AWS Directory Service ##
##################################################
do_domainjoin() {
    #echo "starting domain join script"
    MAX_RETRIES=2
    for i in $(seq 1 $MAX_RETRIES)
    do
	    LOG_MSG=''
        if [ -z "$DIRECTORY_OU" ]; then
            LOG_MSG=$(sudo echo $DOMAIN_PASSWORD | sudo realm join --client-software=winbind -U ${DOMAIN_USERNAME}@${DIRECTORY_NAME} "$DIRECTORY_NAME" -v 2>&1)
			#echo $LOG_MSG >> /tmp/adlog.txt
        else
            LOG_MSG=$(sudo echo $DOMAIN_PASSWORD | sudo realm join --client-software=winbind -U ${DOMAIN_USERNAME}@${DIRECTORY_NAME} "$DIRECTORY_NAME" --computer-ou="$DIRECTORY_OU" -v 2>&1)
			#echo $LOG_MSG >> /tmp/adlog.txt
        fi
        STATUS=$?
        if [ $STATUS -eq 0 ]; then
		    if echo "$LOG_MSG" | grep -q "Successfully enrolled machine in realm"; then
			echo "########## SUCCESS: realm join successful ##########"
            break
			fi
        else
            if echo "$LOG_MSG" | grep -q "Already joined to this domain"; then
                echo "Already joined to this domain : $LOG_MSG"
                STATUS=0
                break
            fi
        fi
        sleep 5
    done

    if [ $STATUS -ne 0 ]; then
        echo "***Failed: realm join failed: $LOG_MSG" && exit 1
    fi
    echo "########## SUCCESS: realm join successful ##########"
}

##############################
## Configure nsswitch.conf  ##
##############################
config_nsswitch() {
    # Edit nsswitch config
    NSSWITCH_CONF_FILE=/etc/nsswitch.conf
    sudo sed -i 's/^\s*passwd:.*$/passwd:     compat winbind/' $NSSWITCH_CONF_FILE
    sudo sed -i 's/^\s*group:.*$/group:      compat winbind/' $NSSWITCH_CONF_FILE
    sudo sed -i 's/^\s*shadow:.*$/shadow:     compat winbind/' $NSSWITCH_CONF_FILE
}

###################################################
## Configure id-mappings in Samba                ##
###################################################
config_samba() {
    AD_INFO=$(sudo adcli info ${DIRECTORY_NAME} | grep '^domain-short = ' | awk '{print $3}')
    sudo sed -i".pre-join" -r\
        "/^\[global\]/a\\
        idmap config * : backend = autorid\n\
        idmap config * : range = 100000000-2100000000\n\
        idmap config * : rangesize = 100000000\n\
        idmap config ${AD_INFO} : backend = rid\n\
        idmap config ${AD_INFO} : range = 65536 - 99999999\n\
        winbind refresh tickets = yes\n\
        kerberos method = secrets and keytab\n\
        winbind enum groups = no\n\
        winbind enum users = no
        /^\s*idmap/d;\
        /^\s*kerberos\s+method/d;\
        /^\s*winbind\s+refresh/d;\
        /^\s*winbind\s+enum/d"\
        /etc/samba/smb.conf

    sudo cp /etc/samba/smb.conf /tmp

    # Flushing Samba Winbind databases
    sudo net cache flush

    # Restarting Winbind daemon
    sudo service winbind restart 2>/dev/null
}

print_vars() {
    ##echo "REGION = $REGION"
    #echo "DIRECTORY_ID = $DIRECTORY_ID"
    echo "DIRECTORY_NAME = $DIRECTORY_NAME"
    #echo "DIRECTORY_OU = $DIRECTORY_OU"
    #echo "REALM = $REALM"
    #echo "DNS_IP_ADDRESS1 = $DNS_IP_ADDRESS1"
    #echo "DNS_IP_ADDRESS2 = $DNS_IP_ADDRESS2"
    echo "COMPUTER_NAME = $COMPUTER_NAME"
    echo "hostname = $(hostname)"
    echo "LINUX_DISTRO = $LINUX_DISTRO"
}

reconfigure_samba() {
    sudo sed -i 's/kerberos method = system keytab/kerberos method = secrets and keytab/g' /etc/samba/smb.conf
    sudo service winbind restart 2>/dev/null
    if [ $? -ne 0 ]; then
        sudo systemctl restart winbind 2>/dev/null
        if [ $? -ne 0 ]; then
            sudo service winbind restart 2>/dev/null
        fi
    fi
}

##################################################
## Main entry point ##############################
##################################################


REALM=$(echo "$DIRECTORY_NAME" | tr [a-z] [A-Z])

set_hostname
configure_hosts_file
if [ -z $REGION ]; then
    get_region
fi

MAX_RETRIES=8
for i in $(seq 1 $MAX_RETRIES)
do
    echo "[$i] Attempt installing components"
    install_components
    if [ $? -eq 0 ]; then
        break
    fi
    sleep 30
done

## Configure DNS even if DHCP option set is used.
do_dns_config
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
sudo systemctl restart sshd 2>/dev/null
if [ $? -ne 0 ]; then
   sudo systemctl restart ssh 2>/dev/null
   if [ $? -ne 0 ]; then
      sudo service sshd restart
   fi
   if [ $? -ne 0 ]; then
      sudo service ssh restart
   fi
fi

print_vars
is_directory_reachable
if [ $? -eq 0 ]; then
    config_nsswitch
    config_samba
    do_domainjoin
    reconfigure_samba
else
    echo "**Failed: Unable to reach DNS server"
    exit 1
fi

echo "Script execution completed"
exit 0
