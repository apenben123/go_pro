playtoken.so:
	g++ -fPIC -c com_play_token.cpp -o com_play_token.o
	g++ -fPIC -c play_token.cpp -o play_token.o
	g++ -shared -o libplaytoken.so com_play_token.o play_token.o
	mv ./libplaytoken.so ../lib
	rm -f com_play_token.o play_token.o
clean:
	rm -f libplaytoken.so com_play_token.o play_token.o
