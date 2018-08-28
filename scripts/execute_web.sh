for host in isucon1 isucon2
do
    ssh $host ". .profile && ${1}"
done
