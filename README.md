# ECB_breaker

This is a black-box attack on an oracle that exploits the statelessness of AES-128-ECB and the block size (16 bytes) to decrypt a secret message. This sort of attack could be used on vulnerable webservers (implementing ECB encryption) to extract information on user data, and even achieve authentication as admin.
