#!/usr/bin/expect
set user [lindex $argv 0]
set ip [lindex $argv 1]
set password [lindex $argv 3]
set port [lindex $argv 2]
spawn ssh $user@$ip -p $port
expect {
        "fingerprint"  {send "yes\r"}
}
expect {
        "password"  {send "$password\r"}
}
interact