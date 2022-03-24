#!/bin/bash


if [ $(id -u) != "0" ]; then
echo 'ERROR! Please su root and try again!
'
exit 0
fi


os=$(cut -f 1 -d ' ' /etc/redhat-release)
release=$(grep -o "[0-9]" /etc/redhat-release |head -n1)
arch=`arch`
random=`cat /dev/urandom | tr -cd 'A-Z0-9' | head -c 5`
IP=`curl -s -L http://cpanel.net/showip.cgi`
if [ ! -f /etc/redhat-release ] || [ "$os" != "CentOS" ] || [ "$release" != "7" ]; then
echo 'ERROR! Please use CentOS Linux release 7 x86_64!
'
exit 0
fi

clear
############################################################
echo '	Welcome to vCyberPanel:
A shell script auto Custom & Install CyberPanel for your CentOS Server Release 7 x86_64.
								Thanks you for using!
'


hostname_set="vcyberpanel.`hostname -f`.local"
echo -n 'Enter your hostname ['$hostname_set']: '
read hostname_i
if [ "$hostname_i" = "" ]; then
hostname_i=$hostname_set
fi
if [ ! -f /usr/bin/nslookup ]; then
yum -y install bind-utils  >/dev/null 2>&1
fi
IP_hostname=`nslookup $hostname_i 8.8.4.4| awk '/^Address: / { print $2 }'`
if [ "$IP_hostname" = "" ]; then
IP_hostname='UNKNOWN'
fi
if [ "$IP_hostname" != "$IP" ]; then
echo 'ERROR! 
Your Server IP Address is ==> '$IP'!
Your Hostname '$hostname_i' point to IP Address ==> '$IP_hostname'!
Please point your Domain DNS A record '$hostname_i' to '$IP' and try again!'
exit 0
fi

echo 'Hostname => '$hostname_i''
hostnamectl set-hostname $hostname_i



# echo -n 'Which MariaDB Server version you want to install [5.5|10.0|10.1|10.2|10.3]: '
# read MariaDB_Server_version
# if [ "$MariaDB_Server_version" != "5.5" ] && [ "$MariaDB_Server_version" != "10.0" ] && [ "$MariaDB_Server_version" != "10.1" ] && [ "$MariaDB_Server_version" != "10.2" ] && [ "$MariaDB_Server_version" != "10.3" ]; then
# MariaDB_Server_version=10.0
# fi
# echo 'MariaDB Server version => '$MariaDB_Server_version''

# echo '# MariaDB '$MariaDB_Server_version' CentOS repository list - created 2018-06-21 03:11 UTC
# # http://downloads.mariadb.org/mariadb/repositories/
# [mariadb]
# name = MariaDB
# baseurl = http://yum.mariadb.org/'$MariaDB_Server_version'/centos7-amd64
# gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
# gpgcheck=1' > /etc/yum.repos.d/MariaDB.repo




yum -y install e2fsprogs nano screen wget curl zip unzip net-tools which psmisc sysstat
# chattr +i /etc/yum.repos.d/MariaDB.repo


sh <(curl https://cyberpanel.net/install.sh || wget -O - https://cyberpanel.net/install.sh)


cp /usr/local/lsws/conf/httpd_config.conf /usr/local/lsws/conf/httpd_config.conf.bak.$random
s='*:80' ; r='127.0.0.1:8080' ; sed -i "s#$s#$r#g" /usr/local/lsws/conf/httpd_config.conf;
s='	allow                                   ALL' ; r='	allow                                   ALL, 127.0.0.1T' ; sed -i "s#$s#$r#g" /usr/local/lsws/conf/httpd_config.conf;

echo '
listener SSL {
  address                 127.0.0.1:8443
  secure                  1
  keyFile                 /usr/local/lsws/admin/conf/webadmin.key
  certFile                /usr/local/lsws/admin/conf/webadmin.crt
}
' >> /usr/local/lsws/conf/httpd_config.conf



#s='background:linear-gradient(154deg,#008fe2 0,#00b29c 100%)' ; r='background:linear-gradient(154deg,#008fe2 0,#00ff59 100%)'
#num=$(( $RANDOM % 5 + 1))
#if [ $num = '1' ]; then r='background:linear-gradient(154deg,#008fe2 0,#00ff59 100%)'; fi
#if [ $num = '2' ]; then r='background:linear-gradient(154deg,#008fe2 0,#00fff1 100%)'; fi
#if [ $num = '3' ]; then r='background:linear-gradient(154deg,#047773 0,#00fff6 100%)'; fi
#if [ $num = '4' ]; then r='background:linear-gradient(154deg,#00a851 0,#00b29c 100%)'; fi
#if [ $num = '5' ]; then r='background:linear-gradient(154deg,#00a851 0,#1eedb9 100%)'; fi
#cp /usr/local/lscp/cyberpanel/static/baseTemplate/assets/finalBase/finalBase.css /usr/local/lscp/cyberpanel/static/baseTemplate/assets/finalBase/finalBase.css.bak.$random
#sed -i "s/$s/$r/g" /usr/local/lscp/cyberpanel/static/baseTemplate/assets/finalBase/finalBase.css

echo '
auth_mechanisms=plain login
' >> /etc/dovecot/dovecot.conf
service dovecot restart



# mv /usr/local/lscp/cyberpanel/phpmyadmin/config.sample.inc.php /usr/local/lscp/cyberpanel/phpmyadmin/config.inc.php
# cp /usr/local/lscp/cyberpanel/phpmyadmin/config.inc.php /usr/local/lscp/cyberpanel/phpmyadmin/config.inc.php.bak.$random
# echo '
# $i++;
# $cfg['Servers'][$i]['auth_type'] = 'cookie';
# /* Server parameters */
# $cfg['Servers'][$i]['host'] = 'localhost:3307';
# $cfg['Servers'][$i]['compress'] = false;
# $cfg['Servers'][$i]['AllowNoPassword'] = false;
# ' >> /usr/local/lscp/cyberpanel/phpmyadmin/config.inc.php

s='A604800' ; r='A31536000' ; sed -i "s#$s#$r#g" /usr/local/lsws/conf/httpd_config.conf;


curl -k -L --silent https://127.0.0.1:8090
curl -k -L --silent https://'$IP':8090

/usr/bin/cyberpanel createPackage --owner admin --packageName 1GB --diskSpace 1000 --bandwidth 0 --emailAccounts 1000 --dataBases 1000 --ftpAccounts 1000 --allowedDomains 1000
/usr/bin/cyberpanel createPackage --owner admin --packageName 2GB --diskSpace 2000 --bandwidth 0 --emailAccounts 2000 --dataBases 2000 --ftpAccounts 2000 --allowedDomains 2000
/usr/bin/cyberpanel createPackage --owner admin --packageName 3GB --diskSpace 3000 --bandwidth 0 --emailAccounts 3000 --dataBases 3000 --ftpAccounts 3000 --allowedDomains 3000
/usr/bin/cyberpanel createPackage --owner admin --packageName 4GB --diskSpace 4000 --bandwidth 0 --emailAccounts 4000 --dataBases 4000 --ftpAccounts 4000 --allowedDomains 4000
/usr/bin/cyberpanel createPackage --owner admin --packageName 5GB --diskSpace 5000 --bandwidth 0 --emailAccounts 5000 --dataBases 5000 --ftpAccounts 5000 --allowedDomains 5000
/usr/bin/cyberpanel createPackage --owner admin --packageName 10GB --diskSpace 10000 --bandwidth 0 --emailAccounts 10000 --dataBases 10000 --ftpAccounts 10000 --allowedDomains 10000
/usr/bin/cyberpanel createPackage --owner admin --packageName 15GB --diskSpace 15000 --bandwidth 0 --emailAccounts 15000 --dataBases 15000 --ftpAccounts 15000 --allowedDomains 15000
/usr/bin/cyberpanel createPackage --owner admin --packageName 20GB --diskSpace 20000 --bandwidth 0 --emailAccounts 20000 --dataBases 20000 --ftpAccounts 20000 --allowedDomains 20000
/usr/bin/cyberpanel createPackage --owner admin --packageName 30GB --diskSpace 30000 --bandwidth 0 --emailAccounts 30000 --dataBases 30000 --ftpAccounts 30000 --allowedDomains 30000
/usr/bin/cyberpanel createPackage --owner admin --packageName 50GB --diskSpace 50000 --bandwidth 0 --emailAccounts 50000 --dataBases 50000 --ftpAccounts 50000 --allowedDomains 50000
/usr/bin/cyberpanel createPackage --owner admin --packageName 100GB --diskSpace 100000 --bandwidth 0 --emailAccounts 100000 --dataBases 100000 --ftpAccounts 100000 --allowedDomains 100000
/usr/bin/cyberpanel createPackage --owner admin --packageName Unlimit --diskSpace 0 --bandwidth 0 --emailAccounts 100000 --dataBases 100000 --ftpAccounts 100000 --allowedDomains 0
/usr/bin/cyberpanel createWebsite --package 1GB --owner admin --domainName $hostname_i --email admin@$hostname_i --php 7.2

/usr/bin/cyberpanel issueSSL --domainName $hostname_i
/usr/bin/cyberpanel issueSelfSignedSSL --domainName $hostname_i

s='*:443' ; r='127.0.0.1:8443' ; sed -i "s#$s#$r#g" /usr/local/lsws/conf/httpd_config.conf;
service lsws stop
sleep 10
service lsws restart


yum -y install memcached
service memcached start
chkconfig memcached on

cp /usr/local/lsws/lsphp53/etc/php.ini /usr/local/lsws/lsphp53/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp53/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp53/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp53/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp53/etc/php.ini

cp /usr/local/lsws/lsphp54/etc/php.ini /usr/local/lsws/lsphp54/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp54/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp54/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp54/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp54/etc/php.ini

cp /usr/local/lsws/lsphp55/etc/php.ini /usr/local/lsws/lsphp55/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp55/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp55/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp55/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp55/etc/php.ini

cp /usr/local/lsws/lsphp56/etc/php.ini /usr/local/lsws/lsphp56/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp56/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp56/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp56/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp56/etc/php.ini

cp /usr/local/lsws/lsphp70/etc/php.ini /usr/local/lsws/lsphp70/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp70/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp70/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp70/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp70/etc/php.ini

cp /usr/local/lsws/lsphp71/etc/php.ini /usr/local/lsws/lsphp71/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp71/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp71/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp71/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp71/etc/php.ini

cp /usr/local/lsws/lsphp72/etc/php.ini /usr/local/lsws/lsphp72/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp72/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp72/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp72/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp72/etc/php.ini

cp /usr/local/lsws/lsphp73/etc/php.ini /usr/local/lsws/lsphp73/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp73/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp73/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp73/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp73/etc/php.ini

cp /usr/local/lsws/lsphp74/etc/php.ini /usr/local/lsws/lsphp74/etc/php.ini.bak.$random
sed -i "/^post_max_size/c post_max_size = 500M" /usr/local/lsws/lsphp74/etc/php.ini
sed -i "/^upload_max_filesize/c upload_max_filesize = 500M" /usr/local/lsws/lsphp74/etc/php.ini
sed -i "/^memory_limit/c memory_limit = 500M" /usr/local/lsws/lsphp74/etc/php.ini
sed -i "/^max_execution_time/c max_execution_time = 5000" /usr/local/lsws/lsphp74/etc/php.ini

systemctl restart lscpd

clear
netstat -lntup|grep litespeed

# Install vDDoS Proxy Protection:

latest_version=`/usr/bin/curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/CHANGELOG.txt|grep '*vDDoS-' |awk 'NR==1' |tr -d '*vDDoS-'|tr -d ':'`
/usr/bin/curl -L https://github.com/duy13/vDDoS-Protection/raw/master/vddos-$latest_version.tar.gz -o vddos-$latest_version.tar.gz

originhash=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "vddos-$latest_version.tar.gz" |awk 'NR=1 {print $1}'`
downloadhash=`md5sum vddos-$latest_version.tar.gz | awk 'NR=1 {print $1}'`
if [ "$originhash" != "$downloadhash" ]; then
	echo 'Download vddos-'$latest_version'.tar.gz from Github.com failed! Try Downloading from SourceForge.net...'
	rm -rf vddos-$latest_version.tar.gz
	curl -L https://sourceforge.net/projects/vddos-protection/files/vddos-$latest_version.tar.gz -o vddos-$latest_version.tar.gz

	originhash=`curl -L https://sourceforge.net/projects/vddos-protection/files/md5sum.txt --silent | grep "vddos-$latest_version.tar.gz" |awk 'NR=1 {print $1}'`
	downloadhash=`md5sum vddos-$latest_version.tar.gz | awk 'NR=1 {print $1}'`
	if [ "$originhash" != "$downloadhash" ]; then
		echo 'Download vddos-'$latest_version'.tar.gz from SourceForge.net failed! Try Downloading from Files.voduy.com...'
		rm -rf vddos-$latest_version.tar.gz
		curl -L https://files.voduy.com/vDDoS-Proxy-Protection/vddos-$latest_version.tar.gz -o vddos-$latest_version.tar.gz
	fi

fi

tar -xvf vddos-$latest_version.tar.gz >/dev/null 2>&1
cd vddos-$latest_version
chmod 755 -R *.sh  >/dev/null 2>&1
chmod 755 -R */*.sh  >/dev/null 2>&1
./install.sh master

if [ -f /vddos/vddos ]; then

	curl -L https://github.com/duy13/vDDoS-Layer4-Mapping/raw/master/vddos-layer4-mapping -o /usr/bin/vddos-layer4
	chmod 700 /usr/bin/vddos-layer4

	echo 'Install vDDoS Proxy Protection Done!'

	/root/.acme.sh/acme.sh --set-default-ca  --server  letsencrypt >/dev/null 2>&1

else
	echo 'Install vDDoS Proxy Protection Failed!'
	exit 1
fi



echo '
default http://0.0.0.0:80    http://127.0.0.1:8080    no    no    no           no
default https://0.0.0.0:443  https://127.0.0.1:8443  no    no    /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
' >> /vddos/conf.d/website.conf
/usr/bin/vddos restart >/dev/null 2>&1

if [ ! -f /root/.acme.sh/$hostname_i/fullchain.cer ]; then
yum -y install socat
wget -O -  https://get.acme.sh | sh
/root/.acme.sh/acme.sh --issue -d $hostname_i -w /vddos/letsencrypt
	if [ -f /root/.acme.sh/$hostname_i/fullchain.cer ]; then
	echo '
'$hostname_i' https://0.0.0.0:443  https://127.0.0.1:8090  no    no    /root/.acme.sh/'$hostname_i'/'$hostname_i'.key /root/.acme.sh/'$hostname_i'/fullchain.cer
' >> /vddos/conf.d/website.conf
	/usr/bin/vddos restart >/dev/null 2>&1
	fi
fi

echo '# Default Setting for vddos-add command:
SSL				Auto
DNS_sleep 		66
DNS_alias_mode	no
Cache			no
Security		no
HTTP_Listen		http://0.0.0.0:80
HTTPS_Listen	https://0.0.0.0:443
HTTP_Backend	http://127.0.0.1:8080
HTTPS_Backend	https://127.0.0.1:8443
' > /vddos/auto-add/setting.conf
echo '*/21  *  *  *  * root /usr/bin/vddos-autoadd panel cyberpanel openlitespeed' >> /etc/crontab
echo '2 2 * * * root acme.sh --upgrade ; vddos-autoadd ssl-again' >> /etc/crontab

curl -L https://github.com/duy13/VDCYBER/raw/master/freeram.sh -o /root/freeram.sh
echo '* * * * * root bash /root/freeram.sh' >> /etc/crontab
echo '13 * * * * root find /usr/local/lsws/cachedata -type f -mmin +59 -delete 2>/dev/null' >> /etc/crontab
echo '@daily root service lscpd restart' >> /etc/crontab
curl -L https://github.com/duy13/VDCYBER/raw/master/cyber-control.zip -o /root/cyber-control.zip
cd /root ; unzip cyber-control.zip; rm -f cyber-control.zip; mv cyber-control /
ln -s /cyber-control/home.sh /usr/bin/cyber-control
chmod 700 /cyber-control/*.sh




cp /etc/sysctl.conf /etc/sysctl.conf.bak.$random
echo 'kernel.printk = 4 4 1 7
kernel.panic = 10
kernel.sysrq = 0
kernel.shmmax = 4294967296
kernel.shmall = 4194304
kernel.core_uses_pid = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
vm.swappiness = 20
vm.dirty_ratio = 80
vm.dirty_background_ratio = 5
fs.file-max = 2097152
net.core.netdev_max_backlog = 262144
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.core.somaxconn = 65535
net.core.optmem_max = 25165824
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv4.neigh.default.gc_interval = 5
net.ipv4.neigh.default.gc_stale_time = 120
net.netfilter.nf_conntrack_max = 10000000
net.netfilter.nf_conntrack_tcp_loose = 0
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_close = 10
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 10
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 20
net.netfilter.nf_conntrack_tcp_timeout_last_ack = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 20
net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 20
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.route.flush = 1
net.ipv4.route.max_size = 8048576
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.tcp_wmem = 4096 87380 33554432
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_orphans = 400000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.ip_nonlocal_bind = 1' >> /etc/sysctl.conf

touch /etc/security/limits.d/nofile.conf
echo '*    soft    nofile 65535'> /etc/security/limits.d/nofile.conf
echo '*    hard    nofile 65535' >> /etc/security/limits.d/nofile.conf

sysctl -p




/usr/bin/curl --silent --header "X-Install: vCyberPanel" https://files.voduy.com/iplog.php

# chattr -i /etc/yum.repos.d/MariaDB.repo
clear
/usr/local/lsws/bin/lshttpd -v
mysql -V


ranpass="$(cat /dev/urandom | tr -cd 'A-Z0-9' | head -c 13)"
/usr/bin/adminPass $ranpass

echo '
=====> Install and Config vCyberPanel Done! <=====
CyberPanel: https://'$hostname_i' or https://'$IP':8090
	username: admin
	password: '$ranpass'

 Please reboot!
'

