package com.shodan.csiot.iotserver;

public class Device {

    private String domain;
    private String id;
    private Float temperature;
    private String picturePath;

    public Device(String id, String domain){
        this.id = id;
        this.domain = domain;
    }

    public String getDomain() {
        return domain;
    }

    public String getId() {
        return id;
    }

    public Float getTemperature() {
        return temperature;
    }

    public void setTemperature(Float temperature) {
        this.temperature = temperature;
    }

    public String getPicturePath() {
        return picturePath;
    }

    public void setPicturePath(String picturePath) {
        this.picturePath = picturePath;
    }
}
