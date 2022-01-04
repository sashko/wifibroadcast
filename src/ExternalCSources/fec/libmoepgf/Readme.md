All this code was taken from https://github.com/moepinet/libmoepgf
Since we only need gf256 for this FEC implementation (and also only need the "shuffle" implementations when optimized, since they are generally the fastest), 
I decided to just copy the right methods from the repository above.
NOTE: the optimized methods generally require a multiple of 8 or 16. The pattern when optimized is generally the same (mul,addmul):
1) use the fastest implementation for as many bytes as there are multiples of (8/16)
2) use the slow (table) implementation for the rest of the bytes
If there is no optimized method available, flat table is used as a fallback

Also note: I only bothered to add NEON and AVX2 flat_table optimized methods. In the rare case of AVX2 not being available,
SSE3 or similar might be a good option, but I did not bother adding them.