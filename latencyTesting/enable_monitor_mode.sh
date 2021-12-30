#!/bin/bash

# wifi card is first param
WIFI_CARD=$1

MY_WIFI_CHANNEL=149 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel


sudo rfkill unblock wifi
#sudo killall ifplugd #stop management of interface

sudo ifconfig $WIFI_CARD down
sudo iw dev $WIFI_CARD set monitor otherbss fcsfail
sudo ifconfig $WIFI_CARD up
sudo iwconfig $WIFI_CARD channel $MY_WIFI_CHANNEL
#sudo iw dev $MY_TX set channel "6" HT40+
#sudo iwconfig $MY_TX rts off

echo "Monitor mode enabled on card $WIFI_CARD"