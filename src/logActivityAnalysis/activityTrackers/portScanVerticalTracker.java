package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

// Same Destination IP different ports
public class portScanVerticalTracker extends tracker {
    private final String dst;
    private Integer scanCount = 0;
    private List<String> dports = new ArrayList<>();
    private final Instant firstSeen;
    private Instant lastSeen;

    public portScanVerticalTracker(String src, String dst, String dport, Instant firstSeen) {
        this.src = src;
        this.dst = dst;
        this.dports.add(dport);
        this.scanCount+=1;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    public void portScanAttempt(String dport, Instant lastSeen){
        if (!(this.dports.contains(dport))){
            this.dports.add(dport);
            this.lastSeen = lastSeen;
            this.scanCount+=1;
        }
    }

    public Integer getScanCount() {
        return scanCount;
    }

    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nDestination IP: " + dst +
                "\nNumber of Ports Scanned: " + scanCount +
                "\nPorts Targeted:\n- " + String.join("\n- ", dports) +
                "\nFirst Seen " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\n/////////////////////////";
    }
}
