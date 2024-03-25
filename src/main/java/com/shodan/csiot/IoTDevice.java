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

  public static void commandLineInterface(){
    help();
    while(true){
      System.out.printf("> ");
      String command = input.nextLine();
      String keyword = new String(command.split(" ")[0]);
      switch(keyword){
        case "CREATE": createCommand(command); break;
        case "EXIT": exitCommand(); return;
        default: System.out.println("Not implemented yet"); break;
      }
    }
  }

  public static void createCommand(String command){
    String[] splitCommand = command.split(" ");

    if(splitCommand.length != 2){
      System.err.println("Error: not enough args");
      System.err.println("Usage: CREATE <dm> - Create a new domain named 'dm' under your ownership");
    } else {

      String dm = new String(splitCommand[1]);
      try { 
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
        ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());

        out.writeObject(Command.CREATE);
        out.writeObject(dm);
        Response r = (Response) in.readObject();
        switch(r){
          case OK : System.out.println("New domain "+dm+" created"); break;
          case NOK : System.err.println("Error: server could not create domain"); break;
        }

        out.close();
        in.close();
      } catch (IOException e) {
        System.err.println("Error: failed to communicate with server");
      } catch (ClassNotFoundException e) {
        // do nothing, because this class cant "not be found"
      }
    }
    return;
  }

  public static void exitCommand(){
    try {
      ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
      out.writeObject(Command.EOF);
      out.close();
    } catch (IOException e) {
      // do nothing, just exit
    }
    return;
  }

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
    } catch (Exception e) {
      System.err.println(e.getMessage());
      System.exit(1);
    }

    System.out.println("Passed all arg checks");

    commandLineInterface();

    try {
      System.out.println("Shutting down! Closing socket...");
      clientSocket.close();
      input.close();
    } catch (Exception e) {
      System.err.println("Error: failed to close socket.");
      System.exit(1);
    }
    System.exit(0);
  }
}
