package com.shodan.csiot.iotserver;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class User {
    private String username;
    private String certificateFilename;
    private List<Device> ownedDevices;

    public User(String username, String certificate){
        this.username = username;
        this.certificateFilename = certificate;
        this.ownedDevices = new ArrayList<>();
    }

    public User(String username, String certificate, List<Device> ownedDevices){
        this.username = username;
        this.certificateFilename = certificate;
        this.ownedDevices = ownedDevices;
    }

    public String getUsername() {
        return username;
    }

    public String getCertificate() {
        return certificateFilename;
    }

    public List<Device> getOwnedDevices(){
        return this.ownedDevices;
    }

    public boolean addDevice(Device device){
        boolean ret;
        if(this.ownedDevices.contains(device)){
            ret = false;
        } else {
            this.ownedDevices.add(device);
            ret = true;
        }
        return ret;
    }

    public boolean equals(User user) {
        return this.username.equals(user.getUsername()) && this.ownedDevices.equals(user.getOwnedDevices());
    }
}
