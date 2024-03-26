package com.shodan.csiot;

import com.shodan.csiot.iotserver.*;
import com.shodan.csiot.common.UserDevicePair;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.net.Socket;
import java.net.ServerSocket;
import sun.misc.Signal;
import sun.misc.SignalHandler;

public class IoTServer {
  public static void main(String[] args) {
    long startupStart = System.currentTimeMillis();
    StringBuilder logo = new StringBuilder();
    logo.append(".-.    .-----. .--.\n");
    logo.append(": :    `-. .-': .--'\n");
    logo.append(": : .--. : :  `. `.  .--. .--. .-..-. .--. .--.\n");
    logo.append(": :' .; :: :   _`, :' '_.': ..': `; :' '_.': ..'\n");
    logo.append(":_;`.__.':_;  `.__.'`.__.':_;  `.__.'`.__.':_;\n");
    System.out.print(logo.toString());
    System.out.println("More info at: https://github.com/shodanwashere/IoTDevice");

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
      List<UserDevicePair> currentlyLoggedInUDPs = new ArrayList<>();
      Map<String, File> deviceFiles = new HashMap<>();
      // set up currently registered devices
      Map<String, User> users = new HashMap<>();
      Map<String, Device> devices = new HashMap<>();
      Map<String, Domain> domains = new HashMap<>();

      FileReader pfr = new FileReader(passwdFile);
      BufferedReader pbr = new BufferedReader(pfr);

      String pLine;
      while((pLine = pbr.readLine()) != null){
        String[] passwdEntry = pLine.split(":", Integer.MAX_VALUE);
        String username = new String(passwdEntry[0]);
        String password = new String(passwdEntry[1]);
        String deviceLine = new String(passwdEntry[2]);

        User user = new User(username, password);
        if(!deviceLine.equals("")){
          String[] splitDL = deviceLine.split(",");
          for(String devID: splitDL){
            String aDevID = new String(devID);
            Device newDevice = new Device(new String(aDevID));
            devices.put(aDevID, newDevice);
            user.addDevice(newDevice);
          }
        }

        users.put(username, user);
      }

      pbr.close();
      pfr.close();

      FileReader dfr = new FileReader(domainsFile);
      BufferedReader dbr = new BufferedReader(dfr);

      String dLine;
      while((dLine = dbr.readLine()) != null){
        String[] domainEntry = dLine.split(":",Integer.MAX_VALUE);
        String domainName = new String(domainEntry[0]);
        String domainMemberUsernames = new String(domainEntry[1]);
        String domainDeviceIDs = new String(domainEntry[2]);

        Domain newDomain = new Domain(domainName);
        if(!domainMemberUsernames.equals("")){
          String[] memberUsernames = domainMemberUsernames.split(",");
          for(String mu: memberUsernames){
            if(users.containsKey(mu)){
              newDomain.addMember(users.get(mu));
            }
          }
        }

        if(!domainDeviceIDs.equals("")){
          String[] deviceIDs = domainDeviceIDs.split(",");
          for(String d: deviceIDs){
            if(devices.containsKey(d)){
              Device dev = devices.get(d);
              newDomain.addDevice(dev);

            }
          }
        }

        domains.put(domainName, newDomain);
      }

      dbr.close();
      dfr.close();

      for(String d: devices.keySet()){
        Device dev = devices.get(d);
        File deviceDir = new File("devices/"+dev.getId()+"/");
        if(!deviceDir.exists()) deviceDir.mkdirs();
        deviceFiles.put(dev.getId(), deviceDir);
      }

      // open server socket
      ServerSocket srvSocket = new ServerSocket(port);

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

      long startupEnd = System.currentTimeMillis();
      long elapsed = startupEnd - startupStart;
      System.out.println("Startup time: "+elapsed+"ms");
      lg.log("Listening on port "+port);
      while(true)
      {
        Socket cliSocket = srvSocket.accept();
        ServerThread st = new ServerThread();
        try{
          st.set(passwdFile, domainsFile, currentlyLoggedInUDPs, users, devices, domains, deviceFiles, cliSocket);
          threads.add(st); st.start();
          lg.log("got connection at <"+cliSocket.getRemoteSocketAddress().toString()+">");
	      } catch (Exception e) {
	        e.printStackTrace();
	        cliSocket.close();
	        continue;
	      }
      }
    } catch (IOException e) {
      System.exit(1);
    } 
  }
}
