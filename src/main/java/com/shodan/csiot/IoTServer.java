package com.shodan.csiot;

import com.shodan.csiot.iotserver.*;
import com.shodan.csiot.common.UserDevicePair;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.net.Socket;
import java.net.ServerSocket;
import sun.misc.Signal;
import sun.misc.SignalHandler;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class IoTServer {

  private static final int KEY_ITERATIONS = 10000;
  private static final byte[] KEY_SALT = {
          (byte) 0x1a, (byte) 0x5c, (byte) 0x9a, (byte) 0x12, (byte) 0x74, (byte) 0xfa, (byte) 0x18, (byte) 0x29
  };
  private static final int KEY_LENGTH = 128;
  private static final String KEY_ALGORITHM = "PBEWithHmacSHA256AndAES_128";

  public static void main(String[] args) {
    long startupStart = System.currentTimeMillis();
    boolean debug = false;
    if (System.getProperty("com.shodan.csiot.debug") != null)
      debug = System.getProperty("com.shodan.csiot.debug").equals("true");
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
    if(debug) lg.log("[+] Handling command line arguments");
    int port = 12345;
    String keyStoreFilename = null;
    String keyStorePassword = null;
    String passwdFileEncryptionPassword = null;
    String twoFactorAPIKey = null;
    if(args.length >= 5){
      try {
        port = Integer.parseInt(args[0]);
      } catch (NumberFormatException nfe) {
        lg.logErr("Error: expected port number, got "+args[0]+"\nUsage: java -jar iotserver.jar [0-65535] <kesytore> <keystore-password> <2FA-APIKey>");
        System.exit(1);
      }
    }

    if (args.length >= 4) {
      int start = (args.length >= 5) ? 1 : 0;
      passwdFileEncryptionPassword = new String(args[start]);
      keyStoreFilename = new String(args[start + 1]);
      File tks = new File(keyStoreFilename);
      if(!tks.exists()){
        System.err.println("Error: supplied keystore file does not exist");
        System.exit(1);
      }
      try {
        FileInputStream ksFIS = new FileInputStream(tks);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(ksFIS, args[start + 2].toCharArray());
        ksFIS.close();
        keyStorePassword = new String(args[start + 2]);
      } catch (IOException e) {
        System.err.println("Error: keystore password is incorrect");
        System.exit(1);
      } catch (Exception e) {
        System.err.println("Error: "+e.getMessage());
        e.printStackTrace();
        System.exit(1);
      }
      twoFactorAPIKey = new String(args[start + 3]);
    } else {
      System.err.println("Error: not enough args");
      System.err.println("Usage: java -jar iotserver.jar [0-65535] <kesytore> <keystore-password> <2FA-APIKey>");
      System.exit(1);
    }

    if(debug) lg.log("[+] Adding keystore and password to system properties");
    System.setProperty("javax.net.ssl.keyStore", keyStoreFilename);
    System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

    if(debug) lg.log("[+] Checking password file");
    // open passwd file
    File passwdFile = new File("passwd");
    if(!passwdFile.exists()) {
      lg.logErr("Error: passwd file does not exist. Please create a file called 'passwd' with at least one 'user:password' pair.");
      System.exit(1);
    }

    if(debug) lg.log("[+] Checking domains file");
    // open domains file
    File domainsFile = new File("domains");
    if(!domainsFile.exists()){
      lg.logErr("Error: domains file does not exist. Please create a file called 'domains' with at least one 'domain:dev1,dev2,...,devN' pair.");
      System.exit(1);
    }

    try{
      if(debug) lg.log("[+] Configuring user file symmetric key");
      SecretKeyFactory kf = null;
      KeySpec ks = new PBEKeySpec(passwdFileEncryptionPassword.toCharArray(), KEY_SALT, KEY_ITERATIONS, KEY_LENGTH);
      SecretKey secretKey = null;
      kf = SecretKeyFactory.getInstance(KEY_ALGORITHM);
      secretKey = kf.generateSecret(ks);


      // set up a list of threads
      // we'll use this to keep track of how many threads are running
      if(debug) lg.log("[+] Setting up server thread list");
      List<ServerThread> threads = new ArrayList<>();
      if(debug) lg.log("[+] Setting up user device pair list");
      List<UserDevicePair> currentlyLoggedInUDPs = new ArrayList<>();
      if(debug) lg.log("[+] Reading system data into memory");
      Map<String, File> deviceFiles = new HashMap<>();
      // set up currently registered devices
      Map<String, User> users = new HashMap<>();
      Map<String, Device> devices = new HashMap<>();
      Map<String, Domain> domains = new HashMap<>();

      Cipher c = Cipher.getInstance(KEY_ALGORITHM);

      // get encryption parameters
      ObjectInputStream ois = new ObjectInputStream(new FileInputStream("encryption.parameters"));
      byte[] keyParameters = (byte[]) ois.readObject();
      AlgorithmParameters p = AlgorithmParameters.getInstance(KEY_ALGORITHM);
      p.init(keyParameters);
      c.init(Cipher.DECRYPT_MODE, secretKey, p);

      FileInputStream pfis = new FileInputStream(passwdFile);
      CipherInputStream pcis = new CipherInputStream(pfis, c);
      File tmpDecryptedPasswd = File.createTempFile("passwd-",".dec");
      FileOutputStream tdfos = new FileOutputStream(tmpDecryptedPasswd);

      byte[] buffer = new byte[16];
      int bytesRead;
      while((bytesRead = pcis.read(buffer)) != - 1){
        tdfos.write(buffer, 0, bytesRead);
      }
      pfis.close();
      pcis.close();
      tdfos.close();

      FileReader tdfr = new FileReader(tmpDecryptedPasswd);
      BufferedReader pbr = new BufferedReader(tdfr);

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
      tdfr.close();
      pcis.close();
      pfis.close();
      tmpDecryptedPasswd.delete();

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

      if(debug) lg.log("[+] Opening SSL server socket");
      // open server socket
      ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
      SSLServerSocket srvSocket = (SSLServerSocket) ssf.createServerSocket(port);

      // this shutdown hook will mark all threads for shutdown, so they will shutdown safely.
      if(debug) lg.log("[+] Setting up shutdown hook");
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

      if(debug) lg.log("[+] System startup finished");
      long startupEnd = System.currentTimeMillis();
      long elapsed = startupEnd - startupStart;
      System.out.println("Startup time: "+elapsed+"ms");
      lg.log("Listening on port "+port);
      while(true)
      {
        Socket cliSocket = srvSocket.accept();
        ServerThread st = new ServerThread();
        try{
          st.set(passwdFile, domainsFile, currentlyLoggedInUDPs, users, devices, domains, deviceFiles, cliSocket, c, secretKey, p, twoFactorAPIKey);
          threads.add(st); st.start();
          lg.log("got connection at <"+cliSocket.getRemoteSocketAddress().toString()+">");
	      } catch (Exception e) {
	        e.printStackTrace();
	        cliSocket.close();
	        continue;
	      }
      }
    } catch (Exception e) {
      if(debug) {
        System.err.println("FATAL ERROR: "+ e.getMessage());
        e.printStackTrace();
      }
      System.exit(1);
    }
  }
}
