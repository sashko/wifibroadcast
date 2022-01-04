All this code was taken from https://github.com/moepinet/libmoepgf
Since we only need gf256 for this FEC implementation (and also only need the "shuffle" implementations when optimized, since they are generally the fastest), 
I decided to just copy the right methods from the repository above.