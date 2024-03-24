package com.shodan.csiot;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.Socket;

public class IoTDevice {
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
    Socket clientSocket = null;
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
    try {
      clientSocket.close();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
