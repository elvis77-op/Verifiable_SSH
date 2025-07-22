#!/bin/bash

hostname=""
port="22"
destination="root@$hostname"

prv_key="/root/keys/id_rsa"
pub_key="/root/keys/id_rsa.pub"
k_hosts="/root/keys/known_hosts"
ls -la /
if [ -f "$prv_key" ]; then
	echo "private key pair exists"
else 
	echo "generates key pair"
	ssh-keygen -q -t rsa -f /root/keys/id_rsa
        echo "generates and known hosts"
	ssh-keyscan -p $port -H $hostname >> $k_hosts 
fi
echo "ssh public key:"
cat $pub_key

echo "copy the ssh public key and paste it to ~/authorized_keys in TDVM, then press ENTER to continue"
read input

echo "load scripts"
scp -P $port -i $prv_key -o UserKnownHostsFile=$k_hosts /root/scripts/* $destination:~/scripts/
ssh -p $port -i $prv_key -o UserKnownHostsFile=$k_hosts $destination 'chmod +x ~/scripts/*'


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
