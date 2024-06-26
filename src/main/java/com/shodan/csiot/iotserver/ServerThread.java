package com.shodan.csiot.iotserver;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.net.Socket;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.shodan.csiot.common.*;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class ServerThread extends Thread {
  private Logger logger;

  private UserDevicePair currUDP;

  private File passwd;
  private File domainsFile;

  private List<UserDevicePair> currentlyLoggedInUDPs;
  private Map<String, User> users;
  private Map<String, Device> devices;
  private Map<String, Domain> domains;
  private Map<String, File> deviceFiles;

  private Cipher cipher;
  private SecretKey secretKey;
  private AlgorithmParameters encParameters;

  private String twoFactorAPIKey;

  private ObjectInputStream in;
  private ObjectOutputStream out;

  private Socket cliSocket;

  private volatile boolean shutdownInitiated = false;

  public void stopExecution(){
    shutdownInitiated = true;
  }

  public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
          Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);

  public void set(File passwd, File domainsFile, List<UserDevicePair> currentlyLoggedInUDPs, Map<String, User> users, Map<String, Device> devices, Map<String, Domain> domains, Map<String, File> deviceFiles, Socket cliSocket, Cipher cipher, SecretKey secretKey, AlgorithmParameters encParameters, String twoFactorAPIKey) throws Exception {
    // set up socket, file descriptors and shutdown flag
    this.cliSocket = cliSocket;
    this.passwd = passwd;
    this.domainsFile = domainsFile;
    this.deviceFiles = deviceFiles;
    this.currentlyLoggedInUDPs = currentlyLoggedInUDPs;

    this.users = users;
    this.devices = devices;
    this.domains = domains;
    this.cipher = cipher;
    this.secretKey = secretKey;
    this.encParameters = encParameters;
    this.twoFactorAPIKey = twoFactorAPIKey;
  }

  private void createCommand(){
    StringBuilder log = new StringBuilder("CREATE");
    synchronized(domains){
      try {
        String dm = (String) in.readObject();
        log.append(" "+dm);

        // does the domain already exist?
        if(domains.containsKey(dm)){
          throw new Exception("Domain already exists.");
        } else {
          String domainName = new String(dm);
          Domain newDomain = new Domain(domainName);
          newDomain.addMember(currUDP.getUser());
          domains.put(domainName, newDomain);

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

        // does this domain exist?
        if(!domains.containsKey(dm)){
          out.writeObject(Response.NODM);
          log.append(" :: NODM");
          logger.log(log.toString());
          return;
        } else {
          // does the current user have membership on this domain?
          Domain d = domains.get(dm);
          if(!d.getMembers().contains(currUDP.getUser())) {
            out.writeObject(Response.NOPERM);
            log.append(" :: NOPERM");
            logger.log(log.toString());
            return;
          } else {
            // does the referenced user exist?
            synchronized(passwd) {
              if (!users.containsKey(user1)) {
                throw new Exception("User does not exist.");
              } else {
                // all checks passed. add user to domain
                User toAdd = users.get(user1);
                d.addMember(toAdd);
              }
            }
          }
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

  private void registerDeviceCommand(){
    StringBuilder log = new StringBuilder("RD");
    synchronized (domains) {
      try {
        // first, check if the domain exists
        String dm = (String) in.readObject();
        log.append(" "+dm);

        if(!domains.containsKey(dm)){
          out.writeObject(Response.NODM);
          log.append(" :: NODM");
          logger.log(log.toString());
          return;
        } else {
          // does the user have permissions?
          Domain d = domains.get(dm);
          if(!d.getMembers().contains(currUDP.getUser())){
            out.writeObject(Response.NOPERM);
            log.append(" :: NOPERM");
            logger.log(log.toString());
            return;
          } else {
            // register the current device in the domain!
            Device dv = currUDP.getDevice();
            d.addDevice(dv);
          }
        }

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

  private void sendTemperatureCommand(){
    StringBuilder log = new StringBuilder("ET");
    synchronized (deviceFiles) {
      try{
        String temp = (String) in.readObject();
        log.append(" "+temp);
        Float aTemp = Float.parseFloat(temp);

        // open a file
        File deviceDir = deviceFiles.get(currUDP.getDevice().getId());
        File deviceTempFile = new File(deviceDir.getAbsolutePath()+"/temp");
        if(deviceTempFile.exists()) deviceTempFile.delete();
        deviceTempFile.createNewFile();

        currUDP.getDevice().setTemperature(aTemp);

        // model updated. now, write to file
        FileWriter dtfw = new FileWriter(deviceTempFile);
        BufferedWriter dtfbw = new BufferedWriter(dtfw);

        dtfbw.write(temp);
        dtfbw.flush();

        dtfbw.close();
        dtfw.close();
        out.writeObject(Response.OK);
        log.append(" :: OK");
      } catch(Exception e) {
        out.writeObject(Response.NOK);
        log.append(" :: NOK");
      } finally {
        logger.log(log.toString());
        return;
      }
    }
  }

  private void sendImageCommand(){
    StringBuilder log = new StringBuilder("EI");
    synchronized (deviceFiles) {
      try {
        String imageFileName = (String) in.readObject();

        log.append(" "+imageFileName);

        String[] splitFilename = imageFileName.split("\\.");

        String extension = new String(splitFilename[1]);

        if(extension.equals("jpg")){
          out.writeObject(Response.OK);
          log.append(" :: OK");
          // prepare to receive file

          Long imageSize = (Long) in.readObject();
          long bytesRemaining = imageSize;

          File image = new File(deviceFiles.get(currUDP.getDevice().getId()).getAbsolutePath()+"/img."+extension);
          if(image.exists()) image.delete();
          image.createNewFile();

          FileOutputStream fout = new FileOutputStream(image);
          OutputStream foutput  = new BufferedOutputStream(fout);

          byte[] buffer = new byte[1024];
          int bytesRead;
          try{
            while(bytesRemaining>0){
              bytesRead = (Integer) in.readObject();
              in.read(buffer, 0, bytesRead);
              foutput.write(buffer, 0, bytesRead);
              foutput.flush();
              bytesRemaining -= bytesRead;
            }
          } catch(EOFException e) {
            // do nothing
          }

          log.append(" "+imageSize+" bytes -> "+image.getName());

          foutput.close();
          fout.close();

          out.writeObject(Response.OK);

        } else {
          throw new Exception();
        }
      } catch (Exception e) {
        out.writeObject(Response.NOK);
        log.append(" :: NOK" + e.getMessage());
      } finally {
        logger.log(log.toString());
        return;
      }
    }
  }

  private void receiveTemperatureCommand(){
    StringBuilder log = new StringBuilder("RT");
    synchronized (domains) {
      synchronized (deviceFiles) {
        synchronized (passwd) {
          try {
            // first, check if the domain exists
            String dm = (String) in.readObject();
            log.append(" " + dm);
            if (!domains.containsKey(dm)) {
              out.writeObject(Response.NODM);
              log.append(" :: NODM");
            } else {
              // check if the user has permissions to read from this domain
              Domain d = domains.get(dm);
              if (!d.getMembers().contains(currUDP.getUser())) {
                out.writeObject(Response.NOPERM);
                log.append(" :: NOPERM");
              } else {
                // the big check
                // create a new temporary file
                File tempSend = File.createTempFile("tempSend-",".tmp");
                FileWriter tsFW = new FileWriter(tempSend);
                BufferedWriter tsBW = new BufferedWriter(tsFW);

                // from the domain, get all the registered devices
                List<Device> domainRegisteredDevices = d.getRegisteredDevices();
                // for each device
                for (Device rd : domainRegisteredDevices) {
                  // find the owner
                  User ru = null;
                  for (User user : d.getMembers()){
                    ru = user;
                    if(ru.getOwnedDevices().contains(rd)) break;
                  }

                  File rdFile = new File(deviceFiles.get(rd.getId()).getAbsolutePath()+"/temp");

                  FileReader deviceFileReader = new FileReader(rdFile);
                  BufferedReader deviceFileBufferedReader = new BufferedReader(deviceFileReader);

                  String temp = new String(deviceFileBufferedReader.readLine());

                  deviceFileReader.close();
                  deviceFileBufferedReader.close();

                  String deviceIdentification = new String(ru.getUsername() + "-" + rd.getId());
                  StringBuilder tempFileLine = new StringBuilder(deviceIdentification);
                  tempFileLine.append(" :: ");
                  tempFileLine.append(temp);

                  tsBW.write(tempFileLine.toString()); tsBW.newLine();
                  tsBW.flush();
                }

                tsBW.close();
                tsFW.close();

                // now things get intense... let's inform the client that we got the data they want
                out.writeObject(Response.OK);
                log.append(" :: OK");
                // next, the number of bytes we need to send
                long tempSendLength = tempSend.length();
                long bytesRemaining = tempSendLength;
                out.writeObject(tempSendLength);
                log.append(" "+tempSendLength+" bytes");
                FileInputStream fin = new FileInputStream(tempSend);
                InputStream finput = new BufferedInputStream(fin);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while(bytesRemaining>0){
                  bytesRead=finput.read(buffer);
                  out.writeObject(bytesRead);
                  out.write(buffer, 0, bytesRead);
                  out.flush();
                  bytesRemaining -= bytesRead;
                }

                finput.close();
                fin.close();

                tempSend.delete();
                // done
              }
            }

          } catch (Exception e) {
            out.writeObject(Response.NOK);
            log.append(" :: NOK - "+e.getMessage());
          } finally {
            logger.log(log.toString());
            return;
          }
        }
      }
    }
  }

  private void receiveImageCommand(){
    StringBuilder log = new StringBuilder("RI");
    synchronized (deviceFiles) {
      synchronized (domains){
        synchronized (passwd) {
          try {
            // first, check if the device exists!
            String devIdentifier = (String) in.readObject();
            String[] splitDevIdentifier = devIdentifier.split(":");
            String username = new String(splitDevIdentifier[0]);
            String deviceID = new String(splitDevIdentifier[1]);
            log.append(" "+devIdentifier);

            if(!devices.containsKey(deviceID) || !users.containsKey(username)){
              out.writeObject(Response.NOID);
              log.append(" :: NOID");
            } else {
              User owner = users.get(username);
              Device dev = devices.get(deviceID);
              if(!owner.getOwnedDevices().contains(dev)) {
                out.writeObject(Response.NOID);
                log.append(" :: NOID");
              } else {
                // check if user has read permissions for this device's domain
                Domain dom = null; boolean found = false;
                for(String domID: domains.keySet()){
                  dom = domains.get(domID);
                  if(dom.getRegisteredDevices().contains(dev)){
                    found = true; break;
                  }
                }
                if(found){
                  if(!dom.getMembers().contains(currUDP.getUser())){
                    out.writeObject(Response.NOPERM);
                    log.append(" :: NOPERM");
                  } else {
                    // check if the device even HAS data stored
                    if(!deviceFiles.containsKey(deviceID)){
                      out.writeObject(Response.NODATA);
                      log.append(" :: NODATA");
                    } else {
                      File deviceImg = new File(deviceFiles.get(deviceID).getAbsolutePath()+"/img.jpg");
                      if(!deviceImg.exists()){
                        out.writeObject(Response.NODATA);
                        log.append(" :: NODATA");
                      } else {
                        out.writeObject(Response.OK);
                        log.append(" :: OK");
                        // all checks verified. time to send the file
                        long imgSize = deviceImg.length();
                        long bytesRemaining = imgSize;
                        out.writeObject(imgSize);
                        FileInputStream fin = new FileInputStream(deviceImg);
                        InputStream finput = new BufferedInputStream(fin);

                        byte[] buffer = new byte[1024];
                        int bytesRead;
                        while(bytesRemaining>0){
                          bytesRead=finput.read(buffer);
                          out.writeObject(bytesRead);
                          out.write(buffer, 0, bytesRead);
                          out.flush();
                          bytesRemaining -= bytesRead;
                        }

                        finput.close();
                        fin.close();
                      }
                    }
                  }
                } else {
                  throw new Exception("device is not registered in any domain");
                }
              }
            }

          } catch (Exception e) {
            out.writeObject(Response.NOK);
            log.append(" :: NOK");
          } finally {
            logger.log(log.toString());
            return;
          }
        }
      }
    }
  }

  private void myDomainsCommand(){
    StringBuilder log = new StringBuilder("MYDOMAINS");
    try{
      out.writeObject(Response.OK);
      synchronized (domains) {
        Device d = currUDP.getDevice();
        Set<String> domainKeys = domains.keySet();
        for(String dk: domainKeys){
          Domain dom = domains.get(dk);
          if(dom.getRegisteredDevices().contains(d)) {
            out.writeObject(dk);
            out.flush();
          }
        }
        out.writeObject(null);
        out.flush();
      }
      log.append(" :: OK");
    } catch (Exception e) {
      out.writeObject(Response.NOK);
      log.append(" :: NOK");
    } finally {
      logger.log(log.toString());
      return;
    }
  }

  // do not call this method without first performing synchronize(deviceFiles)
  private void updateDeviceFiles(){
    for(String d: devices.keySet()){
      Device dev = devices.get(d);
      File deviceDir = new File("devices/"+dev.getId()+"/");
      if(!deviceDir.exists()) deviceDir.mkdirs();
      deviceFiles.put(dev.getId(), deviceDir);
    }
  }

  // do not call this method without first performing synchronize(passwd)
  private void updatePasswd() throws Exception{
    // now that RAM is updated, write changes to file
    passwd.delete(); passwd.createNewFile(); // dirty hack! anyhoo
    File tmpPasswdFile = File.createTempFile("passwd-",".dec");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, encParameters);
    FileWriter tpfw = new FileWriter(tmpPasswdFile);
    BufferedWriter passwdFileBufferedWriter = new BufferedWriter(tpfw);

    for(String username: users.keySet()){
      User u = users.get(username);
      StringBuilder passwdEntry = new StringBuilder(u.getUsername()+":");

      passwdEntry.append(u.getCertificate()+":");

      List<Device> ownedDevices = u.getOwnedDevices();
      List<String> deviceIDs = new ArrayList<>();
      for(Device d: ownedDevices){
        deviceIDs.add(d.getId());
      }
      passwdEntry.append(String.join(",",deviceIDs));

      passwdFileBufferedWriter.write(passwdEntry.toString());
      passwdFileBufferedWriter.newLine();
    }

    passwdFileBufferedWriter.close();

    FileInputStream tpfis = new FileInputStream(tmpPasswdFile);
    FileOutputStream pfos = new FileOutputStream(passwd);
    CipherOutputStream pcos = new CipherOutputStream(pfos, cipher);

    byte[] buffer = new byte[16];
    int bytesRead;
    while((bytesRead = tpfis.read(buffer)) != -1) {
      pcos.write(buffer, 0, bytesRead);
    }

    pcos.close();
    pfos.close();
    tpfis.close();
    tmpPasswdFile.delete();
  }

  // do not call this method without first performing synchronize(domains)
  private void updateDomains() throws Exception{
    // now that RAM is updated, write changes to file
    domainsFile.delete(); domainsFile.createNewFile(); // dirty hack! anyhoo
    FileWriter domainsFileWriter = new FileWriter(domainsFile);
    BufferedWriter domainsFileBufferedWriter = new BufferedWriter(domainsFileWriter);

    for(String domainName: domains.keySet()){
      Domain d = domains.get(domainName);
      StringBuilder domainEntry = new StringBuilder(d.getName()+":");

      List<User> members = d.getMembers();
      List<String> memberUsernames = new ArrayList<>();
      for(User m : members){
        memberUsernames.add(m.getUsername());
      }
      domainEntry.append(String.join(",",memberUsernames)+":");

      List<Device> devices = d.getRegisteredDevices();
      List<String> deviceIDs = new ArrayList<>();
      for(Device dev: devices){
        deviceIDs.add(dev.getId());
      }
      domainEntry.append(String.join(",",deviceIDs));

      domainsFileBufferedWriter.write(domainEntry.toString());
      domainsFileBufferedWriter.newLine();
    }

    domainsFileBufferedWriter.close();
    domainsFileWriter.close();
  }

  private boolean authenticationRoutine() throws Exception{
    boolean debug = false;
    if (System.getProperty("com.shodan.csiot.debug") != null)
      debug = System.getProperty("com.shodan.csiot.debug").equals("true");
    String cliUser = (String) in.readObject();
    if(debug) logger.log("[+] Received username from client");

    long authNonce = new Random().nextLong();
    out.writeObject(authNonce);
    out.flush();
    if(debug) logger.log("[+] Sent nonce to client");

    ByteBuffer authBuffer = ByteBuffer.allocate(Long.BYTES);
    authBuffer.putLong(authNonce);
    byte[] authNonceBytes = authBuffer.array();
    MessageDigest md = MessageDigest.getInstance("SHA256");
    byte[] authNonceHash = md.digest(authNonceBytes);
    if(debug) logger.log("[+] Nonce hash calculated");

    // initial standard auth
    synchronized (passwd) {
      boolean isRegistered = false;
      if(users.containsKey(cliUser)) {
        if(debug) logger.log("[+] User is already registered.");
        isRegistered = true;
      }

      out.writeObject(isRegistered);
      out.flush();

      long recNonce = (long) in.readObject();
      if(debug) logger.log("[+] Received nonce back.");
      byte[] signature = (byte[]) in.readObject();
      if(debug) logger.log("[+] Signature received from client.");

      Certificate userCert;
      if(isRegistered) {
        logger.log("AUTH :: User is already registered. Authenticating...");
        User user = users.get(cliUser);
        String userCertFilename = user.getCertificate();
        FileInputStream ucfis = new FileInputStream("userCerts/" + userCertFilename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        userCert = cf.generateCertificate(ucfis);
        ucfis.close();
      } else {
        userCert = (Certificate) in.readObject();
      }
      if(debug) logger.log("[+] Loaded user certificate");

      PublicKey userPK = userCert.getPublicKey();
      Cipher sigDec = Cipher.getInstance("RSA");
      sigDec.init(Cipher.DECRYPT_MODE, userPK);
      byte[] decryptedHash = sigDec.doFinal(signature);
      if(Arrays.equals(authNonceHash, decryptedHash)){
        logger.log("AUTH :: User key pair match.");
        out.writeObject(Response.OKUSER);
      } else {
        logger.logErr("AUTH :: Challenge signature could not be verified. Authentication failed.");
        out.writeObject(Response.WRONGPWD);
        return false;
      }

      if(!isRegistered){
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(cliUser);
        if(!matcher.matches()){
          logger.logErr("AUTH :: Invalid email address. Registration failed.");
          out.writeObject(Response.NOKUSER);
          return false;
        }
        byte[] certificateBytes = userCert.getEncoded();
        FileOutputStream os = new FileOutputStream("userCerts/"+cliUser+".cer");
        os.write(certificateBytes);
        os.flush();
        os.close();
        User newUser = new User(cliUser, new String(cliUser+".cer"));
        users.put(cliUser, newUser);
        updatePasswd();
        logger.log("AUTH :: New user registered");
        out.writeObject(Response.OKNEWUSER);
      }
    }

    logger.log("AUTH :: [1/4 locks removed]");

    // second factor
    long c2fa = Math.round(Math.random() * 10000); // generate random 5 character code
    String twoFactorCode = String.format("%05d", c2fa);
    StringBuilder requestURL = new StringBuilder("https://lmpinto.eu.pythonanywhere.com/2FA?e=");
    requestURL.append(cliUser);
    requestURL.append("&c=");
    requestURL.append(twoFactorCode);
    requestURL.append("&a=");
    requestURL.append(twoFactorAPIKey);
    URL url = new URL(requestURL.toString());
    HttpURLConnection con = (HttpURLConnection) url.openConnection();
    con.setRequestMethod("GET");
    int status = con.getResponseCode();
    if(status == 200){
      // request made successfully
      logger.log("AUTH :: 2FA code sent. Waiting for response...");
      String receivedCode = (String) in.readObject();
      if(twoFactorCode.equals(receivedCode)){
        logger.log("AUTH :: 2FA code is correct.");
        out.writeObject(Response.OK2FA);
      } else {
        logger.logErr("AUTH :: Incorrect 2FA code. Authentication failed");
        out.writeObject(Response.WRONG2FA);
        return false;
      }
    }

    logger.log("AUTH :: [2/4 locks removed]");

    String devID = (String) in.readObject();

    // secondary auth - device id
    synchronized (passwd) {
      User thisUser = users.get(cliUser);
      if(devices.containsKey(devID)){
        Device cliDevice = devices.get(devID);

        //check if device is already registered
        Boolean deviceAlreadyRegistered = false;
        for(String u: users.keySet()){
          User user = users.get(u);
          if(!user.equals(thisUser) && user.getOwnedDevices().contains(cliDevice)){
            deviceAlreadyRegistered = true;
            break;
          }
        }
        if(deviceAlreadyRegistered) {
          logger.logErr("AUTH :: Device has already been registed by another user. Authentication failed.");
          out.writeObject(Response.NOKDEVID);
          return false;
        } else {
          // check if this user is already logged in
          Boolean deviceAlreadyAuthenticated = false;

          for(UserDevicePair loggedInUDP:  currentlyLoggedInUDPs){
            deviceAlreadyAuthenticated = loggedInUDP.getUser().equals(thisUser) && loggedInUDP.getDevice().equals(cliDevice);
            break;
          }

          if(deviceAlreadyAuthenticated) {
            logger.logErr("AUTH :: User has already logged in with this device in another client. Authentication failed.");
            out.writeObject(Response.NOKDEVID);
            return false;
          } else {
            thisUser.addDevice(cliDevice);
          }
          logger.log(" AUTH :: Device check passed.");
          out.writeObject(Response.OKDEVID);
        }
      } else {
        Device newDevice = new Device(devID);
        devices.put(devID, newDevice);
        thisUser.addDevice(newDevice);
        logger.log("AUTH :: New device registered.");
        out.writeObject(Response.OKDEVID);
        synchronized (deviceFiles) {
          updateDeviceFiles();
        }
      }
      updatePasswd();
    }

    logger.log("AUTH :: [3/4 locks removed]");

    // final check -> executable name and size
    {
      String executableName = (String) in.readObject();

      Boolean executableNamesAreEqual = executableName.equals("iotdevice-1.0.jar");

      File exe = new File("iotdevice-1.0.jar");

      long nonce = new Random().nextLong();

      out.writeObject(nonce);
      out.flush();

      // https://stackoverflow.com/questions/4485128/how-do-i-convert-long-to-byte-and-back-in-java
      ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
      buffer.putLong(nonce);
      byte[] nonceBytes = buffer.array();

      byte[] exeBytes = Files.readAllBytes(exe.toPath());
      byte[] concat = new byte[nonceBytes.length + exeBytes.length];
      System.arraycopy(nonceBytes, 0, concat, 0, nonceBytes.length);
      System.arraycopy(exeBytes, 0, concat, nonceBytes.length, exeBytes.length);

      // get concat SHA256 hash
      md = MessageDigest.getInstance("SHA256");
      byte[] calculatedHash = md.digest(concat);
      byte[] receivedHash = (byte[]) in.readObject();

      Boolean executablesAreSame = Arrays.equals(calculatedHash, receivedHash);

      if(executableNamesAreEqual && executablesAreSame){
        logger.log("AUTH :: Executable test passed.");
        out.writeObject(Response.OKTESTED);
      } else {
        logger.logErr("AUTH :: Executable test failed. Authentication failed.");
        out.writeObject(Response.NOKTESTED);
        return false;
      }
    }

    logger.log("AUTH :: [4/4 locks removed]");


    // if you reached this point, congrats, you're authenticated! time to create a user-device-pair and add you to the list
    currUDP = new UserDevicePair(users.get(cliUser), devices.get(devID));
    synchronized (currentlyLoggedInUDPs) {
      currentlyLoggedInUDPs.add(currUDP);
    }
    logger.log("AUTH :: "+currUDP.getUser().getUsername()+"-"+currUDP.getDevice().getId()+" has logged in successfully.");
    logger.setThreadName(currUDP.getUser().getUsername()+"-"+currUDP.getDevice().getId());

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
          case RD: this.registerDeviceCommand(); break;
          case ET: this.sendTemperatureCommand(); break;
          case EI: this.sendImageCommand(); break;
          case RT: this.receiveTemperatureCommand(); break;
          case RI: this.receiveImageCommand(); break;
          case MYDOMAINS: this.myDomainsCommand(); break;
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
