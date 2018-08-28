for host in isucon3
do
    ssh $host ". .profile && ${1}"
done
