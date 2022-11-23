#include "../src/WBTransmitter.h"
#include "../src/HelperSources/SocketHelper.hpp"
#include "../src/HelperSources/SchedulingHelper.hpp"
#include "../src/UDPWfibroadcastWrapper.hpp"
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <ctime>
#include <sys/resource.h>
#include <cassert>
#include <chrono>
#include <memory>
#include <string>
#include <memory>
#include <vector>
#include <thread>

int main(int argc, char *const *argv) {
  int opt;
  TOptions options{};
  // input UDP port
  int udp_port = 5600;

  RadiotapHeader::UserSelectableParams wifiParams{20, false, 0, false, 1};

  std::cout << "MAX_PAYLOAD_SIZE:" << FEC_MAX_PAYLOAD_SIZE << "\n";

  while ((opt = getopt(argc, argv, "K:k:p:u:r:B:G:S:L:M:n:")) != -1) {
	switch (opt) {
	  case 'K':options.keypair = optarg;
		break;
	  case 'k':
                options.enable_fec=true;
                if (std::string(optarg) == std::string("h264")){
                  options.tx_fec_options.variable_input_type =FEC_VARIABLE_INPUT_TYPE::RTP_H264;
                }else if(std::string(optarg) == std::string("h265")){
                  options.tx_fec_options.variable_input_type =FEC_VARIABLE_INPUT_TYPE::RTP_H265;
                }else if(std::string(optarg) == std::string("mjpeg")){
                  options.tx_fec_options.variable_input_type =FEC_VARIABLE_INPUT_TYPE::RTP_MJPEG;
                }else{
                  options.tx_fec_options.variable_input_type =FEC_VARIABLE_INPUT_TYPE::NONE;
                  options.tx_fec_options.fixed_k =static_cast<int>(std::stoi(optarg));
                }
		break;
	  case 'p':
                options.tx_fec_options.overhead_percentage = std::stoi(optarg);
		break;
	  case 'u':udp_port = std::stoi(optarg);
		break;
	  case 'r':options.radio_port = std::stoi(optarg);
		break;
	  case 'B':wifiParams.bandwidth = std::stoi(optarg);
		break;
	  case 'G':wifiParams.short_gi = (optarg[0] == 's' || optarg[0] == 'S');
		break;
	  case 'S':wifiParams.stbc = std::stoi(optarg);
		break;
	  case 'L':wifiParams.ldpc = std::stoi(optarg);
		break;
	  case 'M':wifiParams.mcs_index = std::stoi(optarg);
		break;
	  case 'n':
		std::cerr << "-n is deprecated. Please read https://github.com/Consti10/wifibroadcast/blob/master/README.md \n";
		exit(1);
	  default: /* '?' */
	  show_usage:
		fprintf(stderr,
				"Usage: %s [-K tx_key] [-k FEC_K or rtp video codec as string] [-p FEC_PERCENTAGE] [-u udp_port] [-r radio_port] [-B bandwidth] [-G guard_interval] [-S stbc] [-L ldpc] [-M mcs_index] interface \n",
				argv[0]);
		fprintf(stderr, "Radio MTU: %lu\n", (unsigned long)FEC_MAX_PAYLOAD_SIZE);
		fprintf(stderr, "WFB version "
						WFB_VERSION
						"\n");
		exit(1);
	}
  }
  if (optind >= argc) {
	goto show_usage;
  }
  options.wlan = argv[optind];

  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&radiotapHeader,sizeof(RadiotapHeader));
  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader80211n, sizeof(OldRadiotapHeaders::u8aRadiotapHeader80211n));
  //RadiotapHelper::debugRadiotapHeader((uint8_t*)&OldRadiotapHeaders::u8aRadiotapHeader, sizeof(OldRadiotapHeaders::u8aRadiotapHeader));
  SchedulingHelper::setThreadParamsMaxRealtime();

  try {
	UDPWBTransmitter udpwbTransmitter{wifiParams, options, SocketHelper::ADDRESS_LOCALHOST, udp_port};
	udpwbTransmitter.runInBackground();
        while (true){
          std::cout << udpwbTransmitter.createDebug();
          std::this_thread::sleep_for(std::chrono::seconds(1));
        }
  } catch (std::runtime_error &e) {
	fprintf(stderr, "Error: %s\n", e.what());
	exit(1);
  }
  return 0;
}
