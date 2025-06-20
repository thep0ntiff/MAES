all:
	g++ -std=c++11 client.cpp -o client2 -pthread
	g++ -std=c++11 server.cpp -o server2 -pthread

clean:
	rm client server
