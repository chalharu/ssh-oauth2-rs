#!/bin/ash

yesno() {
    ! [ "$1" = "no" ]
}

. /etc/init.d/sshd
start_pre

if [ -z "$DEVICE_AUTHORIZE_URL" -o  -z "$TOKEN_URL" -o -z "$CLIENT_ID" ]; then
  echo "env is empty"
  exit 1
fi

sed -ri 's/DEVICE_AUTHORIZE_URL/'"$(echo $DEVICE_AUTHORIZE_URL | sed 's/\//\\\//g')"'/' /etc/pam.d/sshd.pam
sed -ri 's/TOKEN_URL/'"$(echo $TOKEN_URL | sed 's/\//\\\//g')"'/' /etc/pam.d/sshd.pam
sed -ri 's/CLIENT_ID/'"$(echo $CLIENT_ID | sed 's/\//\\\//g')"'/' /etc/pam.d/sshd.pam

/usr/sbin/sshd.pam -De
