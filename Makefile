run: sniffer.py
	sudo apt-get install libpcap-dev
	sudo pip3 install pypcap
	chmod 755 ./packet-sniffer.py
