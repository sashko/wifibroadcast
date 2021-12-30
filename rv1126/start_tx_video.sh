#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one

TAOBAO="wlx00e0863200b9" #Taobao card
ASUS="wlx244bfeb71c05" #ASUS card
RV1126="wlan0"

#MY_TX=$TAOBAO
MY_TX=$RV1126

FEC_K=10
FEC_PERCENTAGE=50

MY_WIFI_CHANNEL=149 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel

# had to remove the sudo stuff, since there is no differentiation in buildroot

rfkill unblock wifi
#sudo killall ifplugd #stop management of interface

ifconfig $MY_TX down
iw dev $MY_TX set monitor otherbss fcsfail
ifconfig $MY_TX up
iwconfig $MY_TX channel $MY_WIFI_CHANNEL
#sudo iw dev $MY_TX set channel "6" HT40+
#sudo iwconfig $MY_TX rts off

wfb_tx -k $FEC_K -p $FEC_PERCENTAGE -u 5600 -r 60 -M 5 -B 20 -K /oem/drone.key  $MY_TX 
