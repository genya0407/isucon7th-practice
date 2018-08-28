for host in isucon1 isucon2
do
    scp ./server/autofs/* root@$host:/etc/
    ssh root@$host "sudo systemctl restart autofs"
done
