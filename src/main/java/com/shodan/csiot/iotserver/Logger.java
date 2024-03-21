package com.shodan.csiot.iotserver;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.Locale;

public class Logger {
  private String threadName;  

  public Logger(String threadName) {
    this.threadName = threadName;
  }

  public void log(String m) {
    Date now = new Date();
    String timestamp = new SimpleDateFormat("HH:mm:ss", Locale.ENGLISH).format(now);
    StringBuilder log = new StringBuilder("<");
    log.append(threadName);
    log.append("> [");
    log.append(timestamp);
    log.append("] ");
    log.append(m);
    System.out.println(log.toString());
  }
}
