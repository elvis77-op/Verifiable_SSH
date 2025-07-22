#!/bin/bash
# define the address and port of TDVM here
hostname=""
port="22"
destination="root@$hostname"

prv_key="/root/keys/id_rsa"
pub_key="/root/keys/id_rsa.pub"
k_hosts="/root/keys/known_hosts"

if [ -f "$prv_key" ]; then
	echo "private key pair exists"
else 
	echo "generates key pair"
	ssh-keygen -q -t rsa -f /root/keys/id_rsa
        echo "generates and known hosts"
	ssh-keyscan -p $port -H $hostname >> $k_hosts 
	echo "copy the ssh public key below and paste it to /root/.ssh/authorized_keys in TDVM, then press ENTER to continue"
	cat $pub_key
	read input

	ssh -i $prv_key -o UserKnownHostsFile=$k_hosts $destination 'passwd -l root'
	echo "password loggin banned"
	echo "load scripts"
	scp -P $port -i $prv_key -o UserKnownHostsFile=$k_hosts /root/scripts/* $destination:~/scripts/
	ssh -p $port -i $prv_key -o UserKnownHostsFile=$k_hosts $destination 'chmod +x ~/scripts/*'
fi

while true; do
	echo "enter the name of the script to execute it in TDVM: [os-release.sh, ps.sh, whoami.sh], or enter q to quit:"
	read input
	if [[ "$input" == "q" ]]; then
		echo "going to stop vssh"
		break
	else
		ssh -p $port -i $prv_key -o UserKnownHostsFile=$k_hosts $destination "~/scripts/$input"
	fi
done
