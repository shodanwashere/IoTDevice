package com.shodan.csiot.iotserver;

public class ServerThread implements Runnable {
  private Logger logger = null;

  public ServerThread() {
  }

  public void run() {
    logger = new Logger(Thread.currentThread().getName()); // getting thread name on new thread. doing this on the constructor will get the name of the main thread
    logger.log("I'm a thread!");
  }
}
