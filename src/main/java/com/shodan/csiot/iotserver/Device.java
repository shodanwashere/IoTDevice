package com.shodan.csiot.iotserver;

public class Device {


    private String id;
    private Float temperature;
    private String picturePath;

    public Device(String id){
        this.id = id;
        temperature = null;
        picturePath = null;
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

    public boolean equals(Device device){
        return this.id.equals(device.getId()) && this.temperature.equals(device.getTemperature()) && this.picturePath.equals(device.getPicturePath());
    }
}
