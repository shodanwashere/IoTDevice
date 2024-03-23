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

public class IoTServer {
  public static void main(String[] args) {

    // handle args
    int port = 12345;
    if(args.length >= 1){
      try {
        port = Integer.parseInt(args[0]);
      } catch (NumberFormatException nfe) {
        System.err.println("Error: expected port number, got "+args[0]);
        System.err.println("Usage: iotserver <0-65535>");
        System.exit(1);
      }
    }

    // open passwd file
    File passwdFile = new File("passwd");
    if(!passwdFile.exists()) {
    	System.err.println("passwd file does not exist. Please create a file called 'passwd' with at least one 'user:password' pair.");
      System.exit(1);
    }

    // set up password file writers and readers
    FileReader     pwfFR;
    FileWriter     pwfWR;
    BufferedReader pwfBFR;
    BufferedWriter pwfBWR;
    try{
      pwfFR = new FileReader(passwdFile); pwfBFR = new BufferedReader(pwfFR);
      pwfWR = new FileWriter(passwdFile); pwfBWR = new BufferedWriter(pwfWR);
    
      // set up a list of threads
      // we'll use this to keep track of how many threads are running
      List<Thread> threads = new ArrayList<>();

      // this shutdown hook will mark all threads for shutdown, so they will shutdown safely.
      Runtime.getRuntime().addShutdownHook(new Thread(){
        public void run(){
          try {
            System.out.println("Got shutdown! Waiting for threads to die...");
            for(Thread t: threads){
              System.out.print("- "+t.getName()+" :: ");
              if(t.isAlive()) t.join();
              System.out.println("STOPPED");
            }
            System.out.println("Threads dead. Closing file writers and readers.");
            pwfBFR.close();
            pwfBWR.close();
            pwfFR.close();
            pwfWR.close();
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      });
    
      System.out.println("Listening on port "+port);
      // start by
        // (simulating)
        // start a server socket
        //
        // listen for incoming connections
        //
        // on new connection --> open a new thread using ServerThread
      {
        ServerThread st = new ServerThread();
        st.set(pwfBFR, pwfBWR);
        Thread t = new Thread(new ServerThread(), "client-ip");
        threads.add(t); t.start();
        System.out.println("got connection at <client-ip>");
      }
      while(true){}
    } catch (FileNotFoundException e) {
      System.err.println("Error: could not open the passwd file");
      e.printStackTrace();
      System.exit(1);
    } catch (IOException e) {
      System.err.println("Error: could not open the passwd file");
      e.printStackTrace();
      System.exit(1);
    }
  }
}
