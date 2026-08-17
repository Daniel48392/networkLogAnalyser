import jdk.swing.interop.SwingInterOpUtils;

import java.time.LocalDateTime;

import static java.lang.Integer.parseInt;

public class log { // CEF - common event format
    private int cef_version;
    private String vendor; // vendor of product
    private String product; // product that generated the event
    private String product_version;
    private int event; // ID of event
    private String event_readable;
    private int severity;

    // Extensions
    private String src; // Source IP
    private String dst; // Destination IP
    private int spt; // Source Port
    private int dpt; // Destination Port
    private String duser; // Destination user
    private String suser; // Source user
    private LocalDateTime rt; // Receipt time
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


        String rawCEF = rawLog.substring(0, dividerOne);
        String rawVendor = rawLog.substring(dividerOne+1, dividerTwo);
        String rawProduct = rawLog.substring(dividerTwo+1, dividerThree);
        String rawProductVersion = rawLog.substring(dividerThree+1, dividerFour);
        String rawEvent = rawLog.substring(dividerFour+1, dividerFive);
        String rawEventReadable = rawLog.substring(dividerFive+1, dividerSix);
        String rawSeverity = rawLog.substring(dividerSix+1, dividerSeven);
        String rawExtensions = rawLog.substring(dividerSeven+1);

        // Tests
        System.out.println(rawCEF);
        System.out.println(rawVendor);
        System.out.println(rawProduct);
        System.out.println(rawProductVersion);
        System.out.println(rawEvent);
        System.out.println(rawEventReadable);
        System.out.println(rawSeverity);
        System.out.println(rawExtensions);

        // TODO 1) pass the mandatory fields to there variables 2) Parse the extensions 3) Add extensions to there fields also learn to ignore fields not in the log object
        // TODO 4) get methods for the log attributes handle null cases



        // Something iterates and calls this log constructor and passes in raw logs
        // constructor Parses rawLog
        // each line of log becomes an instantiated log object
    }

    public static void main(String[] args) {
        new log("CEF:0|VendorB|IDSSystem|v4.1|2001|SQL Injection Attempt|9|src=185.220.101.5 dst=192.168.1.10 spt=39210 dport=80 proto=TCP msg=Malicious SQL syntax detected");
    }
}
