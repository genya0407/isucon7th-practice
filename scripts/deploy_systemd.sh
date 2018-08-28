for host in isucon1 isucon2
do
    scp ./server/isubata.golang.service root@$host:/etc/systemd/system
    ssh $host "sudo systemctl daemon-reload; sudo systemctl restart isubata.golang.service"
done
