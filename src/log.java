import java.time.LocalDateTime;

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
        // Something iterates and calls this log constructor and passes in raw logs
        // constructor Parses rawLog
        // each line of log becomes an instantiated log object
    }
}
