package com.shodan.csiot.common;

/**
 * Class that represents a command line argument.
 * Interpretation of the value is up to the developer when developing a new command for both the server and the client.
 *
 * @author NunoDias,fc56330
 */
public class Argument {
  private String name;
  private String value;

  public Argument(String name, String value){
    this.name = name;
    this.value = value;
  }

  public String getName(){
    return this.name;
  }

  public String getValue(){
    return this.value;
  }
}
