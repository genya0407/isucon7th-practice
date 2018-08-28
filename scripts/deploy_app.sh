for host in isucon1 isucon2
do
    ssh $host ". .profile && cd isubata/webapp/go && git checkout master && git pull && ./server/prepare_for_bench_web.sh"
done
