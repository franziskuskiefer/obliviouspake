EXTRA_PATH="-I ~/lib/Botan-1.10.3/build/include/ -L ~/lib/Botan-1.10.3/"
#if [[ ":$LD_LIBRARY_PATH:" != *":/user/cspgr/fk00042/lib/Botan-1.10.3/:"* ]]; then
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/user/cspgr/fk00042/lib/Botan-1.10.3/
	export LD_LIBRARY_PATH
#fi

if [ $# -eq 0 ] 
then
	echo "Usage: $0 [client,server,dh,ospake,spake]"
	exit 1
elif [ $1 = 'client' ] 
then
	g++ SPAKEClient.cpp -pthread -lboost_system -lbotan-1.10 -o spakeClient
elif [ $1 = 'server' ] 
then
	g++ SPAKEServer.cpp -pthread -lboost_system -lbotan-1.10 -o spakeServer
elif [ $1 = 'dh' ] 
then
	g++ DiffieHellman.cpp -pthread -lboost_system -lbotan-1.10 -o dh
elif [ $1 = 'ospake' ] 
then
#	g++  oSpake.cpp IHME.c -pthread -lboost_system -lbotan-1.10 -lgnutls -lgcrypt -o ospake
	g++ -I ~/lib/Botan-1.10.3/build/include/ -L ~/lib/Botan-1.10.3/ oSpake.cpp IHME.c -pthread -lboost_system -lbotan-1.10 -lgnutls -lgcrypt -o ospake
elif [ $1 = 'spake' ] 
then
	g++ Spake.cpp -pthread -lboost_system -lbotan-1.10 -o spake
fi
#g++ SPAKEClient.cpp -pthread -lboost_system -lbotan-1.10 -o spakeClient
#g++ SPAKEServer.cpp -pthread -lboost_system -lbotan-1.10 -o spakeServer
#g++ DiffieHellman.cpp -pthread -lboost_system -lbotan-1.10 -o dh
