APXS = /usr/sbin/apxs
APR = /usr/bin/apr-1-config

HTTP_INCLUDE = `${APXS} -q INCLUDEDIR`
APR_INCLUDE = `${APR} --includes`

all:	
	g++ -I"./includes" -I${HTTP_INCLUDE} -O0 -g3 -Wall -c -fmessage-length=0 -fpermissive -fPIC -MMD -MP -MF"src/json/json_reader.d" -MT"src/json/json_reader.d" -o"src/json/json_reader.o" src/json/json_reader.cpp
	g++ -I"./includes" -I${HTTP_INCLUDE} -O0 -g3 -Wall -c -fmessage-length=0 -fpermissive -fPIC -MMD -MP -MF"src/json/json_value.d" -MT"src/json/json_value.d" -o"src/json/json_value.o" src/json/json_value.cpp
	g++ -I"./includes" -I${HTTP_INCLUDE} -O0 -g3 -Wall -c -fmessage-length=0 -fpermissive -fPIC -MMD -MP -MF"src/json/json_writer.d" -MT"src/json/json_writer.d" -o"src/json/json_writer.o" src/json/json_writer.cpp 
	g++ -I"./includes" -I${HTTP_INCLUDE} ${APR_INCLUDE} -O0 -g3 -Wall -c -fmessage-length=0 -fpermissive -fPIC -MMD -MP -MF"src/mod_auth_tremolo.d" -MT"src/mod_auth_tremolo.d" -o"src/mod_auth_tremolo.o" src/mod_auth_tremolo.cpp
	
	g++ -shared -o"mod_auth_tremolo.so" ./src/mod_auth_tremolo.o  ./src/json/json_reader.o ./src/json/json_value.o ./src/json/json_writer.o -lcrypto -lssl -lboost_date_time
	rm src/*.o
	rm src/*.d
	rm src/json/*.o
	rm src/json/*.d
	
