package com.shodan.csiot.common;

import java.util.List;

public abstract class Command {

  private List<Argument> args;

  public Command(List<Argument> args){
    this.args = args;
  }

  public abstract void run();
}
