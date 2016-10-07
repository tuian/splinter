# Splinter

Linux remote access trojan (RAT)


This is the starting code for a Linux RAT written in C.  I was tired of there being no real Linux RATs, most of the time it's just ncat.  It uses mbedTLS for encryption and miniz (but able to use zlib) compression for all the communications. I'm unsure if I did the crypto correctly, but I feel that it's good enough for now
I started this project to learn C and I've been working on it for a couple months.  If any problems happens or features wanted, please let me know.

rat.c

        -Port is configurable at runtime through the environment variable "P".  It will bind on all interfaces by default.
                -Uses poll to handle multiple connections
        -Capable of calling back via "I" environment variable.

rat-client.c

        -Command history and tab completion provided by readline
        -Currently has 4 native commands:
                .exit - Closes that current client's connection
                .kill - Kills off the rat process and all the client's connection
                download <remote file> <local file> - Chunks a file, compresses it and sends it over.  Will verify the file transfer via SHAA1 hash
                upload <local file> <remote file> - Performs the same operation as download but uploads instead

rat binds and client connects to it
        
        remote shell> P=12345 ./rat
        shell> ./rat-client 127.0.0.1 12345

rat calls back to client
        
        shell ./rat-client 12345
        remote_shell> I=127.0.0.1 P=12345 ./rat

TODO:
        
        Simple:
                -Move the rat.c output inside of DEBUG blocks so it's not spewing everywhere
                -Clean up rat-client.c output so it's a little nicer
                -Change the client command prompt to actually get the target's IP address

        Advanced:
                -Add in SSH-type tunnels to be able to do forward and reverse tunels
                -Add in the ability to fork and bind on a different port or callback via commands

