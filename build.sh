if [ $# -eq 0 ] 
then
	echo "Usage: $0 [client,server,dh,ospake]"
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
	g++ oSpake.cpp IHME.c -pthread -lboost_system -lbotan-1.10 -lgnutls -lgcrypt -o ospake
fi
#g++ SPAKEClient.cpp -pthread -lboost_system -lbotan-1.10 -o spakeClient
#g++ SPAKEServer.cpp -pthread -lboost_system -lbotan-1.10 -o spakeServer
#g++ DiffieHellman.cpp -pthread -lboost_system -lbotan-1.10 -o dh
