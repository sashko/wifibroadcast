//
// Created by consti10 on 18.05.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_

#include <vector>
#include <cstdint>
#include <iostream>
#include "StringHelper.hpp"

/**
 * Debug the n lost packets and the n of packet gaps by for a continuous stream of packets with increasing sequence number.
 */
class SequenceNumberDebugger{
 public:
  SequenceNumberDebugger(){
	gapsBetweenLostPackets.reserve(1000);
  }
  /**
   * Call when a new squence number is received
   * @param seqNr the received sequence number.
   */
  void sequenceNumber(const int64_t seqNr){
	nReceivedPackets++;
	auto delta=seqNr-lastReceivedSequenceNr;
	if(delta<=0){
	  std::cerr<<"ERROR got packet nr:"<<seqNr<<"after packet nr:"<<lastReceivedSequenceNr<<"\n";
	  return;
	}
	if(delta>1){
	  nLostPackets+=delta-1;
	  gapsBetweenLostPackets.push_back(delta);
	}
	lastReceivedSequenceNr=seqNr;
  }
  /**
   * Log information about the lost packets and gaps between them.
   * @param clear clear the already accumulated data.
   */
  void debug(bool clear){
	std::cout<<"N packets received:"<<nReceivedPackets<<"\tlost:"<<nLostPackets<<"\n";
	std::cout<<"Packet gaps:"<<StringHelper::vectorAsString(gapsBetweenLostPackets)<<"\n";
	if(clear){
	  gapsBetweenLostPackets.resize(0);
	}
  }
 private:
  std::int64_t lastReceivedSequenceNr=-1;
  std::int64_t nReceivedPackets=0;
  std::int64_t nLostPackets=0;
  std::vector<int64_t> gapsBetweenLostPackets;
};

#endif //WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_
