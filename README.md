This code originated from https://github.com/svpcom/wifibroadcast \
It was re-written in c++ with the intention to reduce latency, improve syntax, improve documentation 
and modularize the FEC Enc/Dec and Encryption/Decryption part. (represented by FECEncoder/Decoder and Encryptor/Decryptor now).\
By doing so I was able to reduce latency quite a lot (even though the fix was one line of code in the end) and
write simple unit tests that don't require a wifi card.\
I also added some new features, like disabling FEC completely (use k==0 in this case) or disabling encryption to save
cpu resources.


Information about using FEC_K,N==0 or FEC_K,N==1:\
1) If tx uses FEC_K==0 and FEC_N==0 the rx forwards packets without duplicates but with possible packet re-ordering due to multiple wifi cards. Aka "just as you'd expect from UDP" but no duplicates to save bandwidth as soon as possible (if the upper level does re-sending of the same backets, for the lower wb level this is just a new packet, to not confuse anybody here, that'l still work).
2) If tx uses FEC_K==1 and FEC_N==1 the rx forwards packets in order and without duplicates, but when using multiple RX this could mean packets arriving late are dropped even though received (same behaviour as original svpcom)
3) With FEC_K>1 and FEC_N>1 the rx behaves just as you are used from svpcom-wifibroadcast.

You can use FEC_K,N==0 for telemetry in general (as long as the upper level deals with packet re-ordering
And have the option to go for FEC_K,N==1 if your upper level cannot deal with packet re-ordering.

And if you need "packet safety", do the re-sending of packets at the upper level, using a bidirectional FEC_K,N==0 or 1 link
