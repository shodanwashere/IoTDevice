package com.shodan.csiot;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.Socket;
import sun.misc.Signal;
import sun.misc.SignalHandler;
import com.shodan.csiot.common.*;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.SocketFactory;
import java.util.Scanner;

/**
 *
 */
public class IoTDevice {
  public static SSLSocket clientSocket;
  public static Scanner input = new Scanner(System.in);

  private static String username;
  private static Integer deviceID;


  /**
   * Displays a help message to the CLI
   */
  public static void help(){
    System.out.println("Available commands:");
    System.out.println("- CREATE <dm>        - Create a new domain named 'dm' under your ownership");
    System.out.println("- ADD <user> <dm>    - Add another user to the 'dm' domain");
    System.out.println("- RD <dm>            - Register the current device in the 'dm' domain");
    System.out.println("- ET <float>         - Send temperature data to the server");
    System.out.println("- EI <filename.jpg>  - Send image to the server");
    System.out.println("- RT <dm>            - Receive latest temperature data from devices in the 'dm' domain if you have permissions");
    System.out.println("- RI <user>:<dev-id> - Receive the device image from the server, as long as you have permissions");
    System.out.println("- HELP               - Display this message");
    System.out.println("- CLEAR              - Clear the screen");
    System.out.println("- EXIT               - Terminate connection");
  }

  /**
   * Handles the authentication routine on the client-side
   * @param in  Socket input stream
   * @param out Socket output stream
   * @return Was authentication successful?
   */
  private static boolean authenticationRoutine(ObjectInputStream in, ObjectOutputStream out){
    // send user
    try {
      out.writeObject(username);
      // ask user for password

      // using the console class! by using the console class to read the password, we read input
      // while masking the output, allowing for more secure logins!
      String password;
      Console console = System.console();
      if(console != null) {
        password = new String(console.readPassword("Password: "));
      } else {
        return false;
      }

      out.writeObject(password);
      out.flush();
      Response r1 = (Response) in.readObject();
      switch(r1){
        case OKUSER:
        case OKNEWUSER: System.out.println("Password authentication passed."); break;
        case WRONGPWD: System.err.println("Password authentication failed."); return false;
        case NOK: System.err.println("Server communication failed."); return false;
      }

      String toSend = deviceID.toString();
      out.writeObject(toSend);
      out.flush();
      Response r2 = (Response) in.readObject();
      switch(r2){
        case OKDEVID: System.out.println("Device authentication passed."); break;
        case NOKDEVID: System.err.println("Device authentication failed."); return false;
        case NOK: System.err.println("Server communication failed."); return false;
      }

      String executablePath = IoTDevice.class
              .getProtectionDomain()
              .getCodeSource()
              .getLocation()
              .toURI()
              .getPath();
      String executableName = executablePath.substring(executablePath.lastIndexOf("/") + 1);
      out.writeObject(executableName);
      out.flush();
      File exe = new File(executablePath);

      long nonce = (long) in.readObject();

      // https://stackoverflow.com/questions/4485128/how-do-i-convert-long-to-byte-and-back-in-java
      ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
      buffer.putLong(nonce);
      byte[] nonceBytes = buffer.array();

      byte[] exeBytes = Files.readAllBytes(exe.toPath());
      byte[] concat = new byte[nonceBytes.length + exeBytes.length];
      System.arraycopy(nonceBytes, 0, concat, 0, nonceBytes.length);
      System.arraycopy(exeBytes, 0, concat, nonceBytes.length, exeBytes.length);

      // get concat SHA256 hash
      MessageDigest md = MessageDigest.getInstance("SHA256");
      byte[] hash = md.digest(concat);

      out.writeObject(hash);
      out.flush();

      Response r3 = (Response) in.readObject();
      switch(r3){
        case OKTESTED: System.out.println("File authentication passed."); break;
        case NOKTESTED: System.err.println("File authentication failed."); return false;
        case NOK: System.err.println("Server communication failed."); return false;
      }
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
    return true;
  }

  public static void clearScreen() {
    System.out.print("\033[H\033[2J");
    System.out.flush();
  }

  /**
   * Method that deals with the entire command line interface
   * 
   * @param in - Client socket input stream
   * @param out - Client socket output stream
   */
  public static void commandLineInterface(ObjectInputStream in, ObjectOutputStream out){
    // TODO: prepare to authenticate with server
    // TODO: Failover if authentication fails
    if(!authenticationRoutine(in, out)){
      exitCommand(in, out);
      return;
    }
    help();
    while(true){
      System.out.printf("> ");
      String command = input.nextLine();
      String keyword = new String(command.split(" ")[0]);
      switch(keyword){
        case "CREATE": createCommand(command, in, out); break;
        case "ADD": addCommand(command, in, out); break;
        case "RD": registerDeviceCommand(command, in, out); break;
        case "ET": sendTemperatureCommand(command, in, out); break;
        case "EI": sendImageCommand(command, in, out); break;
        case "RT": receiveTemperatureCommand(command, in, out); break;
        case "RI": receiveImageCommand(command, in, out); break;
        case "HELP": help(); break;
        case "CLEAR": clearScreen(); break;
        case "EXIT": exitCommand(in, out); return;
        default: System.out.println("Not implemented yet"); break;
      }
    }
  }

  /**
   * Implements the CREATE command on the client side
   * 
   * @param command - String that contains the CREATE keyword and the @code{dm} parameter
   * @param in - Client socket input stream
   * @param out - Client socket output stream
   */
  public static void createCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: CREATE <dm> - Create a new domain named 'dm' under your ownership");
    } else {

      String dm = new String(splitCommand[1]);
      try { 

        out.writeObject(Command.CREATE);
        out.writeObject(dm);
        Response r = (Response) in.readObject();
        switch(r){
          case OK : System.out.println("New domain "+dm+" created"); break;
          case NOK : System.err.println("Error: server could not create domain"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing, because this class cant "not be found"
      }
    }
    return;
  }

  /**
   * Implements the ADD command on the client side
   *
   * @param command String that contains the CREATE keyword and the @code{dm} parameter
   * @param in Client socket input stream
   * @param out Client socket output stream
   */
  public static void addCommand(String command, ObjectInputStream in, ObjectOutputStream out) {
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 3){
      System.err.println("Error: not enough args");
      System.err.println("Usage: ADD <user> <dm> - Create a new domain named 'dm' under your ownership");
    } else {
      String user = new String(splitCommand[1]);
      String dm = new String(splitCommand[2]);

      try { 
        out.writeObject(Command.ADD);
        Thread.sleep(200);
        out.writeObject(user);
        out.writeObject(dm);
        Response r = (Response) in.readObject();
        switch(r){
          case OK : System.out.println("User "+user+" added to domain "+dm); break;
          case NOPERM: System.err.println("Error: permission denied"); break;
          case NODM: System.err.println("Error: domain "+dm+" doesn't exist"); break;
          case NOK : System.err.println("Error: user could not be added to domain"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing, because this class cant "not be found"
      } catch (InterruptedException e) {
        // do nothing
      }
    }
    return;
  }

  /**
   * Implements the RD command on the client side
   *
   * @param command String that contains the CREATE keyword and the @code{dm} parameter
   * @param in Client socket input stream
   * @param out Client socket output stream
   */
  public static void registerDeviceCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: RD <dm> - Register the current device in the 'dm' domain");
    } else {
      String dm = new String(splitCommand[1]);

      try{
        out.writeObject(Command.RD);
        Thread.sleep(200);
        out.writeObject(dm);
        Thread.sleep(200);
        Response r = (Response) in.readObject();
        switch(r) {
          case OK : System.out.println("Registered the device to domain "+dm); break;
          case NOPERM: System.err.println("Error: permission denied"); break;
          case NODM: System.err.println("Error: domain "+dm+" doesn't exist"); break;
          case NOK : System.err.println("Error: device couldnt be registered"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing
      } catch (InterruptedException e) {
        // do nothing
      }
    }
    return;
  }

  /**
   * Implements the ET command on the client side
   *
   * @param command String that contains the CREATE keyword and the @code{dm} parameter
   * @param in Client socket input stream
   * @param out Client socket output stream
   */
  public static void sendTemperatureCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if (splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: ET <float> - Send temperature data to the server");
    } else {
      String temp = new String(splitCommand[1]);

      try {
        out.writeObject(Command.ET); out.flush();
        Thread.sleep(200);
        out.writeObject(temp); out.flush();
        Thread.sleep(200);
        Response r = (Response) in.readObject();
        switch(r) {
          case OK: System.out.println("Temperature saved on server"); break;
          case NOK: System.err.println("Error: server failed to save temperature"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing
      } catch (InterruptedException e) {
        // do nothing
      }
    }
    return;
  }

  /**
   * Implements the RT command on the client side
   *
   * @param command String that contains the CREATE keyword and the @code{dm} parameter
   * @param in Client socket input stream
   * @param out Client socket output stream
   */
  public static void receiveTemperatureCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if (splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: RT <dm> - Receive latest temperature data from devices in the 'dm' domain if you have permissions");
    } else {
      String dm = new String(splitCommand[1]);

      try {
        out.writeObject(Command.RT);
        Thread.sleep(500);
        out.writeObject(dm);
        Thread.sleep(200);
        Response r = (Response) in.readObject();

        switch(r) {
          case OK: {
            // got OK from the server. prepare to receive file
            File tempRec = new File("tempRec-"+dm+"-"+System.currentTimeMillis()+".txt");
            tempRec.createNewFile();

            Long tempRecLength = (Long) in.readObject();
            long bytesRemaining = tempRecLength;

            FileOutputStream fout = new FileOutputStream(tempRec);
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
              // woah wtf???
            }

            System.out.println("Received "+tempRecLength+" bytes. Saved to "+tempRec.getName());

            foutput.close();
            fout.close();
            break;
          }
          case NODM: System.err.println("Error: domain "+dm+" does not exist"); break;
          case NOPERM: System.err.println("Error: permission denied");
          case NOK: System.err.println("Error: server failed to save temperature"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing
      } catch (InterruptedException e) {
        // do nothing
      }
    }
    return;
  }

  /**
   * Implements the EI command on the client-side
   * @param command String containing the EI keyword and the image filename
   * @param in Socket input stream
   * @param out Socket output stream
   */
  public static void sendImageCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: EI <filename.jpg>  - Send image to the server");
    } else {
      String imgFilename = new String(splitCommand[1]);

      try{

        File image = new File(imgFilename);
        if(!image.exists()){
          System.err.println("Error: file does not exist");
          return;
        }

        out.writeObject(Command.EI);
        Thread.sleep(200);
        out.writeObject(imgFilename);
        Thread.sleep(200);
        Response r = (Response) in.readObject();
        if(r.equals(Response.OK)){
          // prepare to send file

          long imgSize = image.length();
          long bytesRemaining = imgSize;
          out.writeObject(imgSize);
          FileInputStream fin = new FileInputStream(image);
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

          Response r2 = (Response) in.readObject();

          if(!r2.equals(Response.OK)) throw new IOException();
          else System.out.println("Sent "+imgSize+" bytes to server.");

        } else {
          throw new IOException();
        }

      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing
      } catch (InterruptedException e) {
        // do nothing
      }

      return;
    }
  }

  public static void receiveImageCommand(String command, ObjectInputStream in, ObjectOutputStream out){
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: RI <user>:<dev-id> - Receive the device image from the server, as long as you have permissions");
    } else {
      String deviceIdentifier = new String(splitCommand[1]);

      try{
        out.writeObject(Command.RI);
        Thread.sleep(200);
        out.writeObject(deviceIdentifier);
        Thread.sleep(200);
        Response r = (Response) in.readObject();
        switch (r) {
          case OK: {
            String[] splitDeviceIdentifier = deviceIdentifier.split(":");
            StringBuilder filename = new StringBuilder(splitDeviceIdentifier[0]);
            filename.append("-");
            filename.append(splitDeviceIdentifier[1]);
            filename.append(".jpg");

            File download = new File(filename.toString());
            if(download.exists()) download.delete();
            download.createNewFile();

            Long imageSize = (Long) in.readObject();
            long bytesRemaining = imageSize;

            FileOutputStream fout = new FileOutputStream(download);
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

            System.out.println(" "+imageSize+" bytes -> "+download.getName());

            foutput.close();
            fout.close();

            break;
          }
          case NOID: System.err.println("Error: device "+deviceIdentifier+" does not exist"); break;
          case NOPERM: System.err.println("Error: permission denied"); break;
          case NODATA: System.err.println("Error: device "+deviceIdentifier+" has not published any images"); break;
        }
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing
      } catch (InterruptedException e) {
        // do nothing
      }
    }

    return;
  }

  /**
   * Implements an EXIT command instead of CTRL+C
   * 
   * @param in - Client socket input stream
   * @param out - Client socket output stream
   */
  public static void exitCommand(ObjectInputStream in, ObjectOutputStream out){
    try {
      out.writeObject(Command.EOF);
      out.flush();
    } catch (IOException e) {
      // do nothing, just exit
    }
    return;
  }

  /**
   * main method
   */
  public static void main(String[] args){
    // process args
    if(args.length < 5){
      System.err.println("Error: not enough args\nUsage: iotdevice <IP/hostname>[:port] <truststore> <truststore-password> <dev-id> <user-id>");
      System.exit(1);
    }

    try {
      String trustStoreFilename = new String(args[1]);
      String trustStorePassword = new String(args[2]);
      File tts = new File(trustStoreFilename);
      if(!tts.exists()){
        System.err.println("Error: supplied truststore does not exist");
        System.exit(1);
      }
      System.setProperty("javax.net.ssl.trustStore", trustStoreFilename);
      System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

      username = new String(args[4]);
      deviceID = Integer.parseInt(args[3]);

      String address = null;
      int port = 12345;
      String[] addressAndPort = args[0].split(":");
      address = new String(addressAndPort[0]);
      if(addressAndPort.length == 2){
        port = Integer.parseInt(addressAndPort[1]);
      }

      SocketFactory sf = SSLSocketFactory.getDefault();
      clientSocket = (SSLSocket) sf.createSocket(address, port);
      // System.out.println("Passed all arg checks");

      // get streams from socket
      ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
      ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

      // initialize CLI
      commandLineInterface(in, out);

      // if the code reaches this point, that means that the client chose to EXIT
      // time to shut everything down.
      System.out.println("Shutting down! Closing socket...");
      in.close();
      out.close();
      clientSocket.close();
      input.close();
    } catch (Exception e) {
      e.printStackTrace();
      try {
        clientSocket.close();
      } catch(Exception ee) {
        ee.printStackTrace();
      }
    } finally { 
      System.exit(1);
    }
    System.exit(0);
  }
}
