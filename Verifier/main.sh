#!/bin/bash
# define the address and port of VSSH server here
hostname=""
port="22"
destination="root@$hostname"

prv_key="/root/keys/private_ssh_key.pem"
pub_key="/root/keys/public_ssh_key.pem"
k_hosts="/root/keys/known_hosts"
scripts=(/root/scripts/*.sh)

ssh-keyscan -p $port -H $hostname >> $k_hosts 

echo "load scripts"
scp -P $port -i $prv_key -o UserKnownHostsFile=$k_hosts /root/scripts/* $destination:~/scripts/
ssh -p $port -i $prv_key -o UserKnownHostsFile=$k_hosts $destination 'chmod +x ~/scripts/*'


for i in "${!scripts[@]}"; do 
	echo "$i: ${scripts[$i]}"
done

while true; do
	echo "enter the index to execute corresponding script in TDVM or enter q to quit:"
	read input
	if [[ "$input" == "q" ]]; then
		echo "going to stop vssh"
		break
	else
		if [[ "$input" =- ^[0-9]+$ ]] && [ "$input" -lt "${#scripts[@]}" ]; then
			ssh -p $port -i $prv_key -o UserKnownHostsFile=$k_hosts $destination "${scripts[$input]}"
		else
			echo "error: get unexpected input (please enter index from 0 to $(( ${#scripts[@]} - 1 )))"
	fi
done
