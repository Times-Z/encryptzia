#!/usr/bin/expect
set user [lindex $argv 0]
set ip [lindex $argv 1]
set port [lindex $argv 2]
set b64password [lindex $argv 3]
set timeout [lindex $argv 4]

set password [exec echo -n $b64password | base64 -d]

spawn ssh -o ConnectTimeout=$timeout $user@$ip -p $port
set timeout 1
expect {
        "fingerprint"  {
                send "yes\r"
        }
}
set timeout 20
expect {
        "password"  {
                send "$password\r"
        }
}
interact