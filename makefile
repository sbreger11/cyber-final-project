local_server:
	python3 src/server/server.py --logging-level INFO --network-interface local
public_server:
	python3 src/server/server.py --logging-level INFO --network-interface public
client_connect_local:
	python3 src/client/client.py --logging-level INFO -serverIP 127.0.0.1 -serverPORT 5222
client_connect_droplet:
	python3 src/client/client.py --logging-level INFO -serverIP 134.122.117.217 -serverPORT 5222
alt_client_connect_local:
	python3 src/alt_client/client.py --logging-level INFO -serverIP 127.0.0.1 -serverPORT 5222
alt_client_connect_droplet:
	python3 src/alt_client/client.py --logging-level INFO -serverIP 134.122.117.217 -serverPORT 5222