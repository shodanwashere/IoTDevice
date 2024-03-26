package com.shodan.csiot.common;

import com.shodan.csiot.iotserver.Device;
import com.shodan.csiot.iotserver.User;

public class UserDevicePair {

    private User user;
    private Device device;

    public UserDevicePair(User user, Device device){
        this.user = user;
        this.device = device;
    }

    public User getUser() {
        return user;
    }

    public Device getDevice() {
        return device;
    }

    public boolean equals(UserDevicePair udp){
        return this.user.equals(udp.getUser()) && this.device.equals(udp.getDevice());
    }
}
