package com.shodan.csiot;

import com.shodan.csiot.iotserver.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;
import java.net.Socket;
import java.net.ServerSocket;
import sun.misc.Signal;
import sun.misc.SignalHandler;

public class IoTServer {
  public static void main(String[] args) {
    Logger lg = new Logger("main-server");
    // handle args
    int port = 12345;
    if(args.length >= 1){
      try {
        port = Integer.parseInt(args[0]);
      } catch (NumberFormatException nfe) {
        lg.logErr("Error: expected port number, got "+args[0]+"\nUsage: iotserver <0-65535>");
        System.exit(1);
      }
    }

    // open passwd file
    File passwdFile = new File("passwd");
    if(!passwdFile.exists()) {
      lg.logErr("Error: passwd file does not exist. Please create a file called 'passwd' with at least one 'user:password' pair.");
      System.exit(1);
    }

    // open domains file
    File domainsFile = new File("domains");
    if(!domainsFile.exists()){
      lg.logErr("Error: domains file does not exist. Please create a file called 'domains' with at least one 'domain:dev1,dev2,...,devN' pair.");
      System.exit(1);
    }

    try{
      // set up a list of threads
      // we'll use this to keep track of how many threads are running
      List<ServerThread> threads = new ArrayList<>();

      ServerSocket srvSocket = new ServerSocket(port);
      lg.log("Listening on port "+port);

      // this shutdown hook will mark all threads for shutdown, so they will shutdown safely.
      Signal.handle(new Signal("INT"), new SignalHandler() {
        @Override
        public void handle(Signal signal) {
          try {
            lg.log("Got shutdown! Waiting for threads to die...");
            for(ServerThread t: threads){
              if(t.isAlive()){ 
                t.stopExecution();
                t.join();
              }
            }
            lg.log("Closing server socket.");
            srvSocket.close();
            lg.log("Shutting down...");
            System.exit(0);
          } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
          }
        }
      });

      while(true)
      {
        Socket cliSocket = srvSocket.accept();
        ServerThread st = new ServerThread();
        try{
	        st.set(passwdFile, domainsFile, cliSocket);
          threads.add(st); st.start();
          lg.log("got connection at <"+cliSocket.getRemoteSocketAddress().toString()+">");
	      } catch (Exception e) {
	        lg.logErr(e.getMessage());
	        cliSocket.close();
	        continue;
	      }
      }
    } catch (IOException e) {
      System.exit(1);
    } 
  }
}
