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
import com.shodan.csiot.common.*;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

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

  private void createCommand(ObjectInputStream in, ObjectOutputStream out){
    logger.log("Received CREATE - Beginning command processing");
    synchronized(domains){
      try {
        String dm = (String) in.readObject();
        if(domainUserPermissions.containsKey(dm) || domainDeviceList.containsKey(dm)){
          out.writeObject(Response.NOK);
        } else {
          List<String> users = new ArrayList<>();
          users.add(new String("root"));
      
          List<String> devices = new ArrayList<>();
      
          domainUserPermissions.put(dm, users);
          domainDeviceList.put(dm, devices);

          // now that RAM is updated, write changes to file
          domains.delete(); domains.createNewFile(); // dirty hack! anyhoo
          FileWriter domainsFileWriter = new FileWriter(domains);
          BufferedWriter domainsFileBufferedWriter = new BufferedWriter(domainsFileWriter);

	  for(String domain: domainUserPermissions.keySet()){
	    StringBuilder domainEntry = new StringBuilder(domain+":");
	    List<String> userPermissions = domainUserPermissions.get(domain);
	    domainEntry.append(String.join(",",userPermissions)+":");
	    List<String> deviceList = domainDeviceList.get(domain);
	    domainEntry.append(String.join(",",deviceList));

	    domainsFileBufferedWriter.write(domainEntry.toString());
	    domainsFileBufferedWriter.newLine();
	  }

	  domainsFileBufferedWriter.close();
	  domainsFileWriter.close();
	  out.writeObject(Response.OK);
        }
      } catch (IOException e) {
        out.writeObject(Response.NOK);
      } finally { 
        return;
      }
    }
  }

  public void run() {
    Thread.currentThread().setName(cliSocket.getRemoteSocketAddress().toString());
    logger = new Logger(Thread.currentThread().getName());
    while(!shutdownInitiated) {
      try {
        logger.log("Listening for client commands"); 
        ObjectInputStream in = new ObjectInputStream(cliSocket.getInputStream());
        ObjectOutputStream out = new ObjectOutputStream(cliSocket.getOutputStream());

        Command clientCommand = (Command) in.readObject();
        switch(clientCommand){
	        case CREATE: this.createCommand(in, out); break;
          case EOF: this.stopExecution(); break;
        }
	in.close();
	out.close();
      } catch(IOException e) {
        e.printStackTrace();
      } catch (ClassNotFoundException e) {
        e.printStackTrace();
      }
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
