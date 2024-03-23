package com.shodan.csiot.iotserver;
import java.io.BufferedReader;
import java.io.BufferedWriter;

public class ServerThread extends Thread {
  private Logger logger = null;

  private BufferedReader passwdFileBufferedReader;
  private BufferedWriter passwdFileBufferedWriter;

  public void set(BufferedReader passwdFileBufferedReader, BufferedWriter passwdFileBufferedWriter){
    this.passwdFileBufferedReader = passwdFileBufferedReader;
    this.passwdFileBufferedWriter = passwdFileBufferedWriter;
  }

  public void run() {
    logger = new Logger(Thread.currentThread().getName()); // getting thread name on new thread. doing this on the constructor will get the name of the main thread
    logger.log("I'm a thread!");
  }
}
