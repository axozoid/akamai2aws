## 11.02.2019
* added functions for removing IP ranges: removeIpv4CIDR and removeIpv6CIDR;
* using the functions above we're removing `0.0.0.0/0` and `::/0` to make sure the SG is effective;
* moved some text messages into variables for easier format changing;
