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

  private UserDevicePair currUDP;

  private File passwd;
  private File domains;

  private List<UserDevicePair> currentlyLoggedInUDPs;
  private List<Device> devices;

  private ObjectInputStream in;
  private ObjectOutputStream out;

  private Map<String,String> usersAndPasswords = new HashMap<>();
  private Map<String,List<String>> userDeviceList = new HashMap<>();
  private Map<String,List<String>> domainUserPermissions = new HashMap<>();
  private Map<String,List<String>> domainDeviceList = new HashMap<>();

  private Socket cliSocket;

  private volatile boolean shutdownInitiated = false;

  public void stopExecution(){
    shutdownInitiated = true;
  }

  public void set(File passwd, File domains, List<UserDevicePair> currentlyLoggedInUDPs, List<Device> devices, Socket cliSocket) throws Exception {
    // set up socket, file descriptors and shutdown flag
    this.cliSocket = cliSocket;
    this.devices = devices;
    this.passwd = passwd;
    this.domains = domains;
    this.currentlyLoggedInUDPs = currentlyLoggedInUDPs;

    // open the passwd file and copy contents to RAM
    synchronized(passwd){
      FileReader pfr = new FileReader(passwd);
      BufferedReader pbfr = new BufferedReader(pfr);

      String line;
      while((line = pbfr.readLine()) != null){
        String[] tuple = line.split(":", Integer.MAX_VALUE);
          String user = new String(tuple[0]);
          String pass = new String(tuple[1]);
	      usersAndPasswords.put(user, pass); // add passwd file entries to hashmap
          String deviceIDs = new String(tuple[2]);
          List<String> deviceList = new ArrayList<>();

          if(!devices.equals("")){
            for(String d: deviceIDs.split(",")){
              deviceList.add(d);
            }
          }

          userDeviceList.put(user, deviceList);
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
	      String deviceIDs = new String(tuple[2]);
	      List<String> userList = new ArrayList<>();
	      List<String> deviceList = new ArrayList<>();

	      if(!users.equals("")){
	        for(String u: users.split(",")){
	          userList.add(u);
	        }
	      }

	      if(!devices.equals("")){
	        for(String d: deviceIDs.split(",")){
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

  private void createCommand(){
    StringBuilder log = new StringBuilder("CREATE");
    synchronized(domains){
      try {
        String dm = (String) in.readObject();
        log.append(" "+dm);
        if(domainUserPermissions.containsKey(dm) || domainDeviceList.containsKey(dm)){
          out.writeObject(Response.NOK);
          log.append(" :: NOK");
        } else {
          List<String> users = new ArrayList<>();
          users.add(currUDP.getUserID());
      
          List<String> devices = new ArrayList<>();
      
          domainUserPermissions.put(dm, users);
          domainDeviceList.put(dm, devices);

          this.updateDomains();

	        out.writeObject(Response.OK);
          log.append(" :: OK");
        }
      } catch (IOException e) {
        out.writeObject(Response.NOK);
        log.append(" :: NOK");
      } finally {
        logger.log(log.toString());
        return;
      }
    }
  }

  private void addCommand(){
    StringBuilder log = new StringBuilder("ADD");
    synchronized(domains){
      try {
        String user1 = (String) in.readObject();
        log.append(" "+user1);
        String dm = (String) in.readObject();
        log.append(" "+dm);

        if(!(domainUserPermissions.containsKey(dm) && domainDeviceList.containsKey(dm))){
          out.writeObject(Response.NODM);
          log.append(" :: NODM");
          logger.log(log.toString());
          return;
        }

        if(!domainUserPermissions.get(dm).contains(currUDP.getUserID())){
          out.writeObject(Response.NOPERM);
          log.append(" :: NOPERM");
          logger.log(log.toString());
          return;
        }

        synchronized(passwd){
          if(!usersAndPasswords.containsKey(user1)){
            throw new Exception("user does not exist");
          }
        }

        List<String> dmUserPermissions = domainUserPermissions.get(dm);
        if(!dmUserPermissions.contains(user1)){
          dmUserPermissions.add(user1);
        }

        // now that RAM is updated, write changes to file
        this.updateDomains();

        out.writeObject(Response.OK);
        log.append(" :: OK");
      } catch (Exception e) {
        out.writeObject(Response.NOK);
        log.append(" :: NOK");
      } finally {
        logger.log(log.toString());
        return;
      }
    }
  }

  // do not call this method without first performing synchronize(passwd)
  private void updatePasswd() throws Exception{
    // now that RAM is updated, write changes to file
    passwd.delete(); passwd.createNewFile(); // dirty hack! anyhoo
    FileWriter passwdFileWriter = new FileWriter(passwd);
    BufferedWriter passwdFileBufferedWriter = new BufferedWriter(passwdFileWriter);

    for(String user: usersAndPasswords.keySet()){
      StringBuilder passwdEntry = new StringBuilder(user+":");
      String userPassword = usersAndPasswords.get(user);
      passwdEntry.append(userPassword+":");
      List<String> deviceList = userDeviceList.get(user);
      passwdEntry.append(String.join(",",deviceList));

      passwdFileBufferedWriter.write(passwdEntry.toString());
      passwdFileBufferedWriter.newLine();
    }

    passwdFileBufferedWriter.close();
    passwdFileWriter.close();
  }

  // do not call this method without first performing synchronize(domains)
  private void updateDomains() throws Exception{
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
  }

  private boolean authenticationRoutine() throws Exception{
    String cliUser = (String) in.readObject();
    String cliPass = (String) in.readObject();

    // initial standard auth
    synchronized (passwd) {
      if(usersAndPasswords.containsKey(cliUser)){
        logger.log("AUTH :: User is already registered. Authenticating...");
        String srvPass = usersAndPasswords.get(cliUser);
        if(srvPass.equals(cliPass)){
          logger.log("AUTH :: Password match.");
          out.writeObject(Response.OKUSER);
        } else {
          logger.logErr("AUTH :: Incorrect password. Authentication failed.");
          out.writeObject(Response.WRONGPWD);
          return false;
        }
      } else {
        logger.log("AUTH :: User does not exist yet. Registering...");
        usersAndPasswords.put(cliUser, cliPass);
        userDeviceList.put(cliUser, new ArrayList<String>());
        updatePasswd();
        logger.log("AUTH :: New user registered");
        out.writeObject(Response.OKNEWUSER);
      }
    }

    logger.log("AUTH :: [1/3 locks removed]");

    String devID = (String) in.readObject();

    // secondary auth - device id
    synchronized (passwd) {
      Boolean deviceAlreadyRegistered = false;
      for(String u: userDeviceList.keySet()){
        List<String> uDeviceList = userDeviceList.get(u);
        if(!u.equals(cliUser) && uDeviceList.contains(devID)){
          deviceAlreadyRegistered = true;
          break;
        }
      }

      if(deviceAlreadyRegistered) {
        logger.logErr("AUTH :: Device has already been registed by another user. Authentication failed.");
        out.writeObject(Response.NOKDEVID);
        return false;
      } else {
        Boolean deviceAlreadyAuthenticated = false;
        for(UserDevicePair loggedInUDP:  currentlyLoggedInUDPs){
          deviceAlreadyAuthenticated = loggedInUDP.getUserID().equals(cliUser) && loggedInUDP.getDeviceID().equals(devID);
          break;
        }
        if(deviceAlreadyAuthenticated) {
          logger.logErr("AUTH :: User has already logged in with this device in another client. Authentication failed.");
          out.writeObject(Response.NOKDEVID);
          return false;
        } else {
          List<String> cliUserDeviceList = userDeviceList.get(cliUser);
          if (!cliUserDeviceList.contains(devID)) {
            cliUserDeviceList.add(new String(devID));
            updatePasswd();
          }
          logger.log(" AUTH :: Device check passed.");
          out.writeObject(Response.OKDEVID);
        }
      }
    }

    logger.log("AUTH :: [2/3 locks removed]");

    // final check -> executable name and size
    {
      String executableName = (String) in.readObject();
      Long executableSize = (Long) in.readObject();

      Boolean executableNamesAreEqual = executableName.equals("iotdevice-1.0.jar");
      Boolean executableSizesAreEqual = true; // do not make this validation until the project is complete

      if(executableNamesAreEqual && executableSizesAreEqual){
        logger.log("AUTH :: Executable test passed.");
        out.writeObject(Response.OKTESTED);
      } else {
        logger.logErr("AUTH :: Executable test failed. Authentication failed.");
        out.writeObject(Response.NOKTESTED);
        return false;
      }
    }

    logger.log("AUTH :: [3/3 locks removed]");


    // if you reached this point, congrats, you're authenticated! time to create a user-device-pair and add you to the list
    currUDP = new UserDevicePair(new String(cliUser), new String(devID));
    synchronized (currentlyLoggedInUDPs) {
      currentlyLoggedInUDPs.add(currUDP);
    }
    logger.log("AUTH :: "+currUDP.getUserID()+"-"+currUDP.getDeviceID()+" has logged in successfully.");
    logger.setThreadName(currUDP.getUserID()+"-"+currUDP.getDeviceID());

    return true;
  }

  public void run() {
    Thread.currentThread().setName(cliSocket.getRemoteSocketAddress().toString());
    logger = new Logger(Thread.currentThread().getName());

    try {
      this.out = new ObjectOutputStream(cliSocket.getOutputStream());
      this.in = new ObjectInputStream(cliSocket.getInputStream());
    } catch (Exception e) {
      logger.logErr(e.getMessage());
      try {
        this.cliSocket.close();
      } catch (Exception ee) {
        ee.printStackTrace();
      }
      return;
    }

    try {
      if(!authenticationRoutine()) stopExecution();
    } catch (Exception e) {
      logger.log("Authentication Routine :: NOK");
      logger.logErr(e.getMessage());
      try{
        out.writeObject(Response.NOK);
      } catch (Exception ee){
        // do nothing
      }
      stopExecution();
    }

    while(!shutdownInitiated) {
      try {
        logger.log("Listening for client commands"); 

        Command clientCommand = (Command) in.readObject();
        switch(clientCommand){
          case CREATE: this.createCommand(); break;
          case EOF: this.stopExecution(); break;
          case ADD: this.addCommand(); break;
        }
      } catch(IOException e) {
        e.printStackTrace();
      } catch (ClassNotFoundException e) {
        e.printStackTrace();
      }
    }

    // shutdown initiated! time to remove our UDP from the list
    synchronized (currentlyLoggedInUDPs){
      currentlyLoggedInUDPs.remove(currUDP);
    }
    
    try {
      in.close();
      out.close();
      logger.log("Connection closed! Closing socket!");
      cliSocket.close();
    } catch (IOException e) {
      logger.logErr("Socket could not be closed!");
    }
    return;
  }
}
