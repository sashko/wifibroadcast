//
// Created by consti10 on 25.07.23.
//

#ifndef WIFIBROADCAST_RATES_H
#define WIFIBROADCAST_RATES_H

#include <vector>

namespace wifibroadcast{

// Theoretical rate(s)
struct Rate{
  int rate_20mhz_kbits;
  int rate_40mhz_kbits;
};

// From https://mcsindex.com/
static std::vector<Rate> theoretical_rates_5G(){
  return {
      Rate{6500 ,13500},  //mcs0 (VHT0)
      Rate{13000,27000}, //mcs1 (VHT1)
      Rate{19500,40500}, //mcs2
      Rate{26000,54000}, //mcs3
      Rate{39000,81000}, //mcs4
      Rate{52000,108000},//mcs5
      Rate{58500,121500},//mcs6
      Rate{65000,135000},//mcs7
      Rate{13000,27000}, //mcs8  (VHT0 + SS2)
      Rate{26000,54000}, //mcs9  (VHT1 + SS2)
      Rate{39000,81000}, //mcs10 (VHT2 + SS2)
      Rate{52000,108000},//mcs11 (VHT3 + SS2)
  };
}
static Rate get_theoretical_rate_5G(int mcs){
  const auto rates=theoretical_rates_5G();
  if(mcs<rates.size() && mcs>=0){
    return rates[mcs];
  }
  return {-1,-1};
}

// Those values come from running the "increase bitrate until tx errors" test 3 times and taking the lowest (sensible) value of those runs
static std::vector<Rate> openhd_rtl8812au_5G_practical_rates() {
  return {
      Rate{5600 ,11700}, // MCS 0
      Rate{11000,20600}, // MCS 1
      Rate{15000,28400}, // MCS 2
      Rate{19000,33400}, // MCS 3
      Rate{26000,36900}, // MCS 4
      Rate{26000,43500}, // MCS 5
      Rate{32000,48000}, // MCS 6
      Rate{38000,53000}, // MCS 7
      Rate{11000,16700}, // MCS 8
      Rate{19000,30000}, // MCS 9
      Rate{27000,37000}, // MCS 10
      Rate{32000,51000}, // MCS 11
  };
}

static Rate get_practical_rate_5G(int mcs){
  const auto rates=openhd_rtl8812au_5G_practical_rates();
  if(mcs<rates.size() && mcs>=0){
    return rates[mcs];
  }
  return {-1,-1};
}



}

#endif  // WIFIBROADCAST_RATES_H
