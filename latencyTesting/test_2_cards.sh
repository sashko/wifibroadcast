#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one
# and also starts the generator / validator such that we can check if packets are transmitted correctly

TAOBAO="wlx00e0863200b9" #Taobao card
ASUS="wlx244bfeb71c05" #ASUS card


MY_RX=$TAOBAO
#MY_RX="wlan0" #rpi testing
MY_TX=$TAOBAO

WFB_FOLDER="/home/consti10/Desktop/wifibroadcast"
#WFB_FOLDER="/home/pi/Desktop/wifibroadcast"

# enable monitor mode on rx card, start wfb_rx
sh ./enable_monitor_mode.sh $MY_RX

xterm -hold -e $WFB_FOLDER/wfb_rx -u 6200 -r 60 $MY_RX &

# enable monitor mode on tx card, start wfb_tx
sh ./enable_monitor_mode.sh $MY_RX

xterm -hold -e $WFB_FOLDER/wfb_tx -u 6000 -r 60 -M 5 -B 20 $MY_TX &

# start the generator / validator
xterm -hold -e $WFB_FOLDER/udp_generator_validator -u 6000 &

# validate incoming packets
$WFB_FOLDER/udp_generator_validator -u 6200 -v 1