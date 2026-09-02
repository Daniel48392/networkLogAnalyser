package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

// Different destination IP same ports
public class portScanHorizontalTracker extends tracker {
    private List<String> dsts = new ArrayList<>();
    private final String dpt;
    private final Instant firstSeen;
    private Instant lastSeen;

    public portScanHorizontalTracker(String src, String dst, String dport, Instant firstSeen) {
        this.src = src;
        this.dsts.add(dst);
        this.dpt = dport;
        this.count+=1;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    public void portScanAttempt(String dst, Instant lastSeen){
        if (!(this.dsts.contains(dst))){
            this.dsts.add(dst);
            this.lastSeen = lastSeen;
            this.count+=1;
        }
    }


    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nPort Scanned: " + dpt +
                "\nNumber of IP Addresses Targeted: " + count +
                "\nIP Addresses Targeted:\n- " + String.join("\n- ", dsts) +
                "\nFirst Seen " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nThreat Level: " + threatLevel + " " + "|" + threatRisk + "|"+
                "\n/////////////////////////";
    }
}
