sudo rm /var/log/nginx/access.log
sudo rm /var/log/mysql/mysql-slow.log
sudo systemctl restart mysql
sudo systemctl stop isubata.golang.service
sudo systemctl stop nginx
#go tool pprof -seconds 90 -list=main.* http://127.0.0.1:5000/debug/pprof/profile > $HOME/pprof_list_result.txt
