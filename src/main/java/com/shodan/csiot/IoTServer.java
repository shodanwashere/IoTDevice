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

    File domainsFile = new File("domains");
    if(!domainsFile.exists()){
      lg.logErr("Error: domains file does not exist. Please create a file called 'domains' with at least one 'domain:dev1,dev2,...,devN' pair.");
      System.exit(1);
    }

    // open domains file

    // set up domains and password file writers and readers
    FileReader     pwfFR;
    FileWriter     pwfWR;
    BufferedReader pwfBFR;
    BufferedWriter pwfBWR;
    FileReader     dsfFR;
    FileWriter     dsfWR;
    BufferedReader dsfBFR;
    BufferedWriter dsfBWR;
    try{
      pwfFR = new FileReader(passwdFile); pwfBFR = new BufferedReader(pwfFR);
      pwfWR = new FileWriter(passwdFile); pwfBWR = new BufferedWriter(pwfWR);
      dsfFR = new FileReader(domainsFile); dsfBFR = new BufferedReader(dsfFR);
      dsfWR = new FileWriter(domainsFile); dsfBWR = new BufferedWriter(dsfWR);
    
      // set up a list of threads
      // we'll use this to keep track of how many threads are running
      List<Thread> threads = new ArrayList<>();

      ServerSocket srvSocket = new ServerSocket(port);
      lg.log("Listening on port "+port);
      Boolean shutdownInitiated = false;

      // this shutdown hook will mark all threads for shutdown, so they will shutdown safely.
      Signal.handle(new Signal("INT"), new SignalHandler() {
        @Override
        public void handle(Signal signal) {
          try {
            lg.log("Got shutdown! Waiting for threads to die...");
            for(Thread t: threads){
              System.out.print("- "+t.getName()+" :: ");
              if(t.isAlive()){ 
                t.join();
              }
              System.out.println("STOPPED");
            }
            lg.log("Threads dead. Closing file writers and readers.");
            pwfBFR.close();
            pwfBWR.close();
            pwfFR.close();
            pwfWR.close();
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
        st.set(pwfBFR, pwfBWR, dsfBFR, dsfBWR, cliSocket, shutdownInitiated);
        Thread t = new Thread(new ServerThread(), cliSocket.getRemoteSocketAddress().toString());
        threads.add(t); t.start();
        lg.log("got connection at <"+cliSocket.getRemoteSocketAddress().toString()+">");
      }
    } catch (IOException e) {
      System.exit(1);
    } 
  }
}
