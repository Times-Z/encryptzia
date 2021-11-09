#!/usr/bin/expect
set user [lindex $argv 0]
set ip [lindex $argv 1]
set port [lindex $argv 2]
set password [lindex $argv 3]
set timeout [lindex $argv 4]
spawn ssh -o ConnectTimeout=$timeout $user@$ip -p $port
expect {
        "fingerprint"  {send "yes\r"}
}
expect {
        "password"  {send "$password\r"}
}
interact