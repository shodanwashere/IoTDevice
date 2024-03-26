package com.shodan.csiot.iotserver;

import java.util.ArrayList;
import java.util.List;

public class Domain {
    private String name;
    private List<User> members;
    private List<Device> registeredDevices;

    public Domain(String name){
        this.name = name;
        this.members = new ArrayList<>();
        this.registeredDevices = new ArrayList<>();
    }

    public Domain(String name, User owner){
        this.name = name;
        this.members = new ArrayList<>(); this.members.add(owner);
        this.registeredDevices = new ArrayList<>();
    }

    public Domain(String name, List<User> members){
        this.name = name;
        this.members = members;
        this.registeredDevices = new ArrayList<>();
    }

    public Domain(String name, List<User> members, List<Device> registeredDevices){
        this.name = name;
        this.members = members;
        this.registeredDevices = registeredDevices;
    }

    public String getName() {
        return name;
    }

    public List<User> getMembers() {
        return members;
    }

    public List<Device> getRegisteredDevices() {
        return registeredDevices;
    }

    public boolean addMember(User newMember){
        boolean ret;
        if(this.members.contains(newMember)){
            ret = false;
        } else {
            ret = true;
            this.members.add(newMember);
        }
        return ret;
    }

    public boolean addDevice(Device newDevice){
        boolean ret;
        if(this.registeredDevices.contains(newDevice)){
            ret = false;
        } else {
            ret = true;
            this.registeredDevices.add(newDevice);
        }
        return ret;
    }

    public boolean equals(Domain domain){
        return this.name.equals(domain.getName())
                && this.members.equals(domain.getMembers())
                && this.registeredDevices.equals(domain.getRegisteredDevices());
    }
}
