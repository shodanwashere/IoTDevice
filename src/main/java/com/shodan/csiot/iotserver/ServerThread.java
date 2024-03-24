package com.shodan.csiot.iotserver;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.File;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.io.IOException;
import java.net.Socket;

public class ServerThread extends Thread {
  private Logger logger;

  private File passwd;
  private File domains;

  private Map<String,String> usersAndPasswords = new HashMap<>();
  private Map<String,List<String>> domainUserPermissions = new HashMap<>();
  private Map<String,List<String>> domainDeviceList = new HashMap<>();

  private Socket cliSocket;

  private volatile boolean shutdownInitiated = false;

  public void stopExecution(){
    shutdownInitiated = true;
  }

  public void set(File passwd, File domains, Socket cliSocket) throws Exception {
    // set up socket, file descriptors and shutdown flag
    this.cliSocket = cliSocket;
    this.passwd = passwd;
    this.domains = domains;

    // open the passwd file and copy contents to RAM
    synchronized(passwd){
      FileReader pfr = new FileReader(passwd);
      BufferedReader pbfr = new BufferedReader(pfr);

      String line;
      while((line = pbfr.readLine()) != null){
        String[] pair = line.split(":");
	usersAndPasswords.put(new String(pair[0]), new String(pair[1])); // add passwd file entries to hashmap
      }

      pbfr.close();
      pfr.close();
    }

    // open the domains file and copy its contents to RAM
    synchronized(domains){
      FileReader dfr = new FileReader(domains);
      BufferedReader dbfr = new BufferedReader(dfr);

      String line;
      while((line = dbfr.readLine()) != null) {
        String[] tuple = line.split(":", Integer.MAX_VALUE);
	String domain = new String(tuple[0]);
	String users = new String(tuple[1]);
	String devices = new String(tuple[2]);
	List<String> userList = new ArrayList<>();
	List<String> deviceList = new ArrayList<>();

	if(!users.equals("")){
	  for(String u: users.split(",")){
	    userList.add(u);
	  }
	}

	if(!devices.equals("")){
	  for(String d: devices.split(",")){
	    deviceList.add(d);
	  }
	}

	domainUserPermissions.put(domain, userList);
	domainDeviceList.put(domain, deviceList);
      }

      dbfr.close();
      dfr.close();
    }

  }

  public void run() {
    Thread.currentThread().setName(cliSocket.getRemoteSocketAddress().toString());
    logger = new Logger(Thread.currentThread().getName());
    while(!shutdownInitiated) {
    }
    
    try {
      logger.log("Connection closed! Closing socket!");
      cliSocket.close();
    } catch (IOException e) {
      logger.logErr("Socket could not be closed!");
    }
    return;
  }
}
