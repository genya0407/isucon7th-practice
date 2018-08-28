for host in isucon1 isucon2
do
    scp -r ./server/nginx/* root@$host:/etc/nginx/
    ssh $host "sudo systemctl restart nginx"
done
