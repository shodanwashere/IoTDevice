package com.shodan.csiot.iotserver;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;

public class IoTServer {
  public static void main(String[] args) throws Exception {
    System.out.println("I am a server!");

    // open passwd file
    File passwdFile = new File("passwd");
    if(!passwdFile.exists()) {
    	throw new FileNotFoundException("passwd file does not exist. Please create a file called 'passwd' with at least one 'user:password' pair.");
    }

    FileReader pwfFR;
    BufferedReader pwfBFR;

    // create a hashmap
    Map<String, String> passwdMap = new HashMap<>();

    // copy its data line by line via `user:passwd`
    pwfFR = new FileReader(passwdFile);
    pwfBFR = new BufferedReader(pwfFR);

    String line;

    while ((line = pwfBFR.readLine()) != null) {
      String[] pair = line.split(":");
      passwdMap.put(pair[0], pair[1]);
      System.out.println("User "+pair[0]+" is registered");
    }

    pwfBFR.close();
    pwfFR.close();

    Runtime.getRuntime().addShutdownHook(new Thread(){
      public void run(){
	System.out.println("Shutting down! Writing changes to disk...");
	try {
	  FileWriter pwfFW = new FileWriter(passwdFile);
	  BufferedWriter pwfBFW = new BufferedWriter(pwfFW);

	  passwdMap.forEach((user,passwd) -> {
            StringBuilder uppSB = new StringBuilder();
	    uppSB.append(user);
	    uppSB.append(":");
	    uppSB.append(passwd);
	    uppSB.append("\n");
	    try {
	      pwfBFW.write(uppSB.toString());
	      pwfBFW.flush();
	      System.out.println("Written pair to file.");
	    } catch (IOException e){
              e.printStackTrace();
	    }
	  });

	  pwfBFW.close();
	  pwfFW.close();
	} catch (IOException e) {
          e.printStackTrace();
	}
      }
    });

    // start by
      // (simulating)
      // start a server socket
      //
      // listen for incoming connections
      //
      // on new connection --> open a new thread using ServerThread
    ServerThread st = new ServerThread();
    new Thread(st, "client-ip").start();
    System.out.println("spawned a thread");
    while(true){}
  }
}
