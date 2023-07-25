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
      // theoretical:6.5 | 13.5
      // max injection rate possible measured on the bench: 5.7 | 10.4
      Rate{
          5700 - 1000,   // minus 1MBit/s
          14000 - 3000,  // minus 3MBit/s
      },
      // theoretical:13 | 27
      // max injection rate possible measured on the bench: 10.8 | 18.8
      Rate{
          10800 - 1000,  // minus 1MBit/s
          18800 - 3500,  // minus 3.5MBit/s
      },
      //@Norbert: Successfully flown on MCS2 and 7MBit/s video, aka 8.4MBit/s after FEC
      // theoretical:19.5 | 40.5
      // max injection rate possible measured on the bench: 15.2 | 26.6
      Rate{
          15200 - 2000,  // minus 2MBit/s
          26600 - 4000,  // minus 4MBit/s
      },
      // theoretical:26 | 54
      // max injection rate possible measured on the bench: 19.2 | 30+ (out of capabilities of encoder)
      Rate{
          19200 - 3000,  // minus 3MBit/s
          30000 - 5000,  // minus 5MBit/s
      },
      // In general, we only use / recommend MCS 0..3
      // theoretical:39
      {17000, 30000},
      // theoretical:52
      Rate{23000, 30000},
      // theoretical:58.5
      Rate{30000, 30000},
      // theoretical:65
      Rate{30000, 30000},
      //
      // MCS 8 == MCS 0 with 2 spatial streams
      //
      // theoretical 13 | 27
      // measured: ~11.7 | 22.1
      Rate{11700 - 3000, 22100 - 4000},
      // theoretical 26 | 54
      // measured: ~21 | 30+
      Rate{21000 - 3000, 32000 - 4000},
      // theoretical 39 | 81
      // measured: ~22 | none
      // here we already pretty much reach the limit what encoding hw (rpi) can do
      Rate{22000 - 3000, 30000},
      // theoretical 52 | 108
      Rate{30000, 30000},
      // theoretical 78 | 162
      Rate{30000, 30000},
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
