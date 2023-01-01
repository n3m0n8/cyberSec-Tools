# This code was written/learnt while following NeuralNine's Florian Dedov's tutorial
# //// IMPORT \\\\\
# import the socket construct for packaging data over the network
import socket
# import the threading construct for organising processing
import threading
# import the Rivest–Shamir–Adlemanpublic-key algo
import rsa

# /////// COMPILE \\\\

#create two instances of the rsa keys, one as public key and the other as private public_key with 1024 bits
# of entropy - this is for the first client
public_key, private_key = rsa.newkeys(1024)
# for the chat buddy, we set an unset (None in py) public_key:
partner_pub_key = None
# create var for user choice prompt
choice = input('Do You Want to host as the server[press s] or connect as client? [press h]: ')

# IF CHOICE IS TO BE SERVER
if choice == 's':
    # set server var as being an instance of socket.socket constructor
    server = socket.socket(
          # explicitly assign first the default AF_INET ip address family arg
          socket.AF_INET,
          # explicitly assign the default socket stream parameter- i.e. outline that this is a TCP connection 
          #not datagram(UDP) or raw (binary)
          socket.SOCK_STREAM
          )
        server.bind('127.168.1.1', 78299)
    # set the local server to listen for incoming tcp traffic on chosen port
    server.listen()
    # set the client as being instantiated when the server has a connection passing through a TCP 
    # handshake and accepting the host's request to connect to the server this is a multiple assignation of 
    # variable value, the first is client, the second is just a placeholder var in the place of an address
    # (since this chat is hosted/executed on the same server/host computer on the 127 loopback addr).
    client, _ = server.accept()
    # here we also load a copy of our public key as initator of the conversation ( buddy doesn't have a filled 
    # public key yet, so this will fill up his public key) then his private key can open it up to secure the tcp 
    # data flow. save_pkcs1 is used to protect against bruteforcing the initial primitives??? PEM refers to a 
    #particular format
    client.send(
        public_key.save_pkcs1("PEM")
        )
    # fill the buddy's public key with the public key that was just sent: rsa namespace comes in.  then Public_Key
    # function... then the load_pkcs1() method 
    partner_pub_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
# ELSE IF CHOICE IS TO BE CLIENT
elif choice == 'h':
    # mirror image of server socket with same paras:
    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
        )
    # but this time we use connect() meth instead of listen():
    client.connect(
        '127.168.1.1', 78299)
    # mirror image again of the public key process except this time, we first load the PK then send it
    # back with confirmation?
    partner_pub_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(
      public_key.save_pkcs1("PEM")
      )
else:
    exit()
# definition function for sending  message with client being the destination client to send the message to
def sending_messages(clt):
    # so long as the send message def funct is being called...
    while True:
        # message content is whatever is being inputted
        message = input('')
        # client send() the message with encoding
        clt.rsa.encrypt(message.encode(), partner_pub_key)
          # print out the message as it has been sent 
        print('You said: ' + message)
def recieving_messages(clt):
    # mirror image here for reception of messages
    while True:
        # print out the  recieved message
        # prefaced by confirmation
        print('Your buddy said: ' + rsa.decrypt(clt.recv(1024),private_key).decode())
# ///////RUNTIME\\\\\\\
# now set up the threading to handle the incoming/outgoing messages' 
threading.Thread(
# target specifies which callable function (# i.e. the deff'd functions above) are to be called
  target=sending_messages,
  # args tells the threading handler to pass the following as args in that function (in this case it is 
  # the previously created client which is passed as arg1 of the callable func.
  args=(client, )).start()
threading.Thread(target= (recieving_messages), args=(client, )).start()
#start thread at end.
