#   Matus Tvarozny
#     xtvaro00
# IPK 2.projekt(ZETA)
#     Sniffer

CC=g++
CFLAGS=-std=c++17 -Wall 

all:
	$(CC) $(CFLAGS) ipk-sniffer.cpp -lpcap -o ipk-sniffer