package logData;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import static java.lang.Integer.parseInt;


public class log { // CEF - common event format
    private String cef_version;
    private String vendor; // vendor of product
    private String product; // product that generated the event
    private String productVersion;
    private String event; // ID of event
    private String eventReadable;
    private int severity;

    // Extensions
    private String src; // Source IP
    private String dst; // Destination IP
    private String spt; // Source Port
    private String dport; // Destination Port
    private String duser; // Destination user
    private String suser; // Source user
    private Instant rt; // Receipt time
    private String act; // Action
    private String msg;
    private String proto; // Protocol


    public log(String rawLog){
        int dividerOne = rawLog.indexOf("|");
        int dividerTwo = rawLog.indexOf("|", dividerOne +1);
        int dividerThree = rawLog.indexOf("|", dividerTwo +1);
        int dividerFour = rawLog.indexOf("|", dividerThree +1);
        int dividerFive = rawLog.indexOf("|", dividerFour +1);
        int dividerSix = rawLog.indexOf("|", dividerFive +1);
        int dividerSeven = rawLog.indexOf("|", dividerSix +1);

        // Works out where the dividers are between CEF headers
        cef_version = rawLog.substring(0, dividerOne);
        vendor = rawLog.substring(dividerOne+1, dividerTwo);
        product = rawLog.substring(dividerTwo+1, dividerThree);
        productVersion = rawLog.substring(dividerThree+1, dividerFour);
        event = rawLog.substring(dividerFour+1, dividerFive);
        eventReadable = rawLog.substring(dividerFive+1, dividerSix);
        try {
            severity = parseInt(rawLog.substring(dividerSix+1, dividerSeven));
        }
        catch (NumberFormatException e) {
            if (rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("very low") || rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("informational")) {
                severity = 0;
            }
            else if (rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("low")) {
                severity = 3;
            }
            else if (rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("medium")) {
                severity = 5;
            }
            else if (rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("high")) {
                severity = 8;
            }
            else if (rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("very high") || rawLog.substring(dividerSix+1, dividerSeven).toLowerCase().equals("critical")) {
                severity = 10;
            }
        }
        String rawExtensions = rawLog.substring(dividerSeven+1);




        // Checks if the CEF extension exists, and it actually is the extension and not just being read from inside another word
        // So then checks if the extension is either the first extension listed or if it has a blank space behind it to ensure the above
        if (!(rawExtensions.indexOf("src=")==-1) && ((rawExtensions.indexOf("src=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("src=")-1) == ' '))){
            src = rawExtensions.substring(rawExtensions.indexOf("src=")+4, logExtensionParser.spaceFinder(rawExtensions, "src="));
        }
        else {
            src = null;
        }
        if (!(rawExtensions.indexOf("dst=")==-1) && ((rawExtensions.indexOf("dst=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("dst=")-1) == ' '))){
            dst = rawExtensions.substring(rawExtensions.indexOf("dst=")+4, logExtensionParser.spaceFinder(rawExtensions, "dst="));
        }
        else {
            dst = null;
        }
        if (!(rawExtensions.indexOf("spt=")==-1) && ((rawExtensions.indexOf("spt=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("spt=")-1) == ' '))){
            spt = rawExtensions.substring(rawExtensions.indexOf("spt=")+4, logExtensionParser.spaceFinder(rawExtensions, "spt="));
        }
        else {
            spt = null;
        }
        if (!(rawExtensions.indexOf("dport=")==-1) && ((rawExtensions.indexOf("dport=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("dport=")-1) == ' '))){
            dport = rawExtensions.substring(rawExtensions.indexOf("dport=")+6, logExtensionParser.spaceFinder(rawExtensions, "dport="));
        }
        else {
            dport = null;
        }
        if (!(rawExtensions.indexOf("duser=")==-1) && ((rawExtensions.indexOf("duser=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("duser=")-1) == ' '))){
            duser = rawExtensions.substring(rawExtensions.indexOf("duser=")+6, logExtensionParser.spaceFinder(rawExtensions, "duser="));
        }
        else {
            duser = null;
        }
        if (!(rawExtensions.indexOf("suser=")==-1) && ((rawExtensions.indexOf("suser=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("suser=")-1) == ' '))){
            suser = rawExtensions.substring(rawExtensions.indexOf("suser=")+6, logExtensionParser.spaceFinder(rawExtensions, "suser="));
        }
        else {
            suser = null;
        }
        if (!(rawExtensions.indexOf("rt=")==-1) && ((rawExtensions.indexOf("rt=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("rt=")-1) == ' '))){
            try { // Handles it in the case of EpochMilli format
                rt = Instant.ofEpochMilli(Long.parseLong(rawExtensions.substring(rawExtensions.indexOf("rt=") + 3, logExtensionParser.spaceFinder(rawExtensions, "rt=")))); // Fix
            }catch (NumberFormatException e){ // if its date format it will be caught and then the date format will be parsed
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd yyyy HH:mm:ss");
                LocalDateTime dateTime = LocalDateTime.parse(rawExtensions.substring(rawExtensions.indexOf("rt=") + 3, logExtensionParser.spaceFinder(rawExtensions, "rt=")), formatter);
                rt = dateTime.toInstant(ZoneOffset.UTC);
            }
        }
        else {
            rt = null;
        }
        if (!(rawExtensions.indexOf("act=")==-1) && ((rawExtensions.indexOf("act=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("act=")-1) == ' '))){
            act = rawExtensions.substring(rawExtensions.indexOf("act=")+4, logExtensionParser.spaceFinder(rawExtensions, "act="));
        }
        else {
            act = null;
        }
        if (!(rawExtensions.indexOf("msg=")==-1) && ((rawExtensions.indexOf("msg=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("msg=")-1) == ' '))){
            msg = rawExtensions.substring(rawExtensions.indexOf("msg=")+4, logExtensionParser.spaceFinder(rawExtensions, "msg="));
        }
        else {
            msg = null;
        }
        if (!(rawExtensions.indexOf("proto=")==-1) && ((rawExtensions.indexOf("proto=")==0) || (rawExtensions.charAt(rawExtensions.indexOf("proto=")-1) == ' '))){
            proto = rawExtensions.substring(rawExtensions.indexOf("proto=")+6, logExtensionParser.spaceFinder(rawExtensions, "proto="));
        }
        else {
            proto = null;
        }
    }

    public String getCef_version() {
        return cef_version;
    }

    public String getVendor() {
        return vendor;
    }

    public String getProduct() {
        return product;
    }

    public String getProductVersion() {
        return productVersion;
    }

    public String getEvent() {
        return event;
    }

    public String getEventReadable() {
        return eventReadable;
    }

    public int getSeverity() {
        return severity;
    }

    public String getSrc() {
        return src;
    }

    public String getDst() {
        return dst;
    }

    public String getSpt() {
        return spt;
    }

    public String getDport() {
        return dport;
    }

    public String getDuser() {
        return duser;
    }

    public String getSuser() {
        return suser;
    }

    public Instant getRt() {
        return rt;
    }

    public String getAct() {
        return act;
    }

    public String getMsg() {
        return msg;
    }

    public String getProto() {
        return proto;
    }

    @Override
    public String toString() {
        return "logData.log{" +
                "cef_version='" + cef_version + '\'' +
                ", vendor='" + vendor + '\'' +
                ", product='" + product + '\'' +
                ", productVersion='" + productVersion + '\'' +
                ", event='" + event + '\'' +
                ", eventReadable='" + eventReadable + '\'' +
                ", severity=" + severity +
                ", src='" + src + '\'' +
                ", dst='" + dst + '\'' +
                ", spt='" + spt + '\'' +
                ", dport='" + dport + '\'' +
                ", duser='" + duser + '\'' +
                ", suser='" + suser + '\'' +
                ", rt=" + rt +
                ", act='" + act + '\'' +
                ", msg='" + msg + '\'' +
                ", proto='" + proto + '\'' +
                '}';
    }


}
