package com.shodan.csiot;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.Socket;
import sun.misc.Signal;
import sun.misc.SignalHandler;
import com.shodan.csiot.common.*;
import java.util.Scanner;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

public class IoTDevice {
  public static Socket clientSocket;  
  public static Scanner input = new Scanner(System.in);

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
    System.out.println("- EXIT               - Terminate connection");
  }

  /**
   * Method that deals with the entire command line interface
   * 
   * @param in - Client socket input stream
   * @param in - Client socket output stream
   */
  public static void commandLineInterface(ObjectInputStream in, ObjectOutputStream out){
    help();
    while(true){
      System.out.printf("> ");
      String command = input.nextLine();
      String keyword = new String(command.split(" ")[0]);
      switch(keyword){
        case "CREATE": createCommand(command, in, out); break;
        case "ADD": addCommand(command, in, out); break;
        case "HELP": help(); break;
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
   * @param in - Client socket output stream
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
          case NODM: System.err.println("Error: domain "+dm+" doesn't exist."); break;
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
    if(args.length < 3){
      System.err.println("Error: not enough args\nUsage: iotdevice <IP/hostname>[:port] <dev-id> <user-id>");
      System.exit(1);
    }

    int deviceID = 0;
    try {
      deviceID = Integer.parseInt(args[1]);
    } catch (NumberFormatException e){
      System.err.println("Error: device id must be an integer");
      System.exit(1);
    }

    String address = null;
    int port = 12345;
    try {
      String[] addressAndPort = args[0].split(":");
      address = new String(addressAndPort[0]);
      if(addressAndPort.length == 2){
        port = Integer.parseInt(addressAndPort[1]);
      }
      clientSocket = new Socket(address, port);
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
