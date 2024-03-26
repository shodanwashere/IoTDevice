package com.shodan.csiot.common;

public class UserDevicePair {

    private String userID;
    private String deviceID;

    public UserDevicePair(String userID, String deviceID){
        this.userID = userID;
        this.deviceID = deviceID;
    }

    public String getUserID() {
        return userID;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public boolean equals(UserDevicePair udp){
        return this.userID.equals(udp.getUserID()) && this.deviceID.equals(udp.getDeviceID());
    }
}
