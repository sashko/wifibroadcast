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

static std::vector<Rate> openhd_rtl8812au_5G_practical_rates() {
  return {
      Rate{5600 ,0}, // MCS 0
      Rate{11000,0}, // MCS 1
      Rate{15000,0}, // MCS 2
      Rate{19000,0}, // MCS 3
      Rate{26120,0}, // MCS 4
      Rate{33230,0}, // MCS 5
      Rate{33330,0}, // MCS 6
      Rate{36060,0}, // MCS 7
      Rate{5530 ,0}, // MCS 8
      Rate{11480,0}, // MCS 9
      Rate{13810,0}, // MCS 10
      Rate{14240,0}, // MCS 11
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
