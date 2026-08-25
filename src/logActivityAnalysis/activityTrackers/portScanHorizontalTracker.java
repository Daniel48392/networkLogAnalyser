package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

// Different destination IP same ports
public class portScanHorizontalTracker {
    private final String src;
    private List<String> dsts = new ArrayList<>();
    private Integer scanCount = 0;
    private final String dport;
    private final Instant firstSeen;
    private Instant lastSeen;

    public portScanHorizontalTracker(String src, String dst, String dport, Instant firstSeen) {
        this.src = src;
        this.dsts.add(dst);
        this.dport = dport;
        this.scanCount+=1;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    public void portScanAttempt(String dst, Instant lastSeen){
        if (!(this.dsts.contains(dst))){
            this.dsts.add(dst);
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
                "\nPort Scanned: " + dport +
                "\nNumber of IP Addresses Targeted: " + scanCount +
                "\nIP Addresses Targeted:\n- " + String.join("\n- ", dsts) +
                "\nFirst Seen " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\n/////////////////////////";
    }
}
