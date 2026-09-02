package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

// Same Destination IP different ports
public class portScanVerticalTracker extends tracker {
    private final String dst;
    private List<String> dpts = new ArrayList<>();
    private final Instant firstSeen;
    private Instant lastSeen;

    public portScanVerticalTracker(String src, String dst, String dport, Instant firstSeen) {
        this.src = src;
        this.dst = dst;
        this.dpts.add(dport);
        this.count+=1;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
    }

    public void portScanAttempt(String dport, Instant lastSeen){
        if (!(this.dpts.contains(dport))){
            this.dpts.add(dport);
            this.lastSeen = lastSeen;
            this.count+=1;
        }
    }


    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nDestination IP: " + dst +
                "\nNumber of Ports Scanned: " + count +
                "\nPorts Targeted:\n- " + String.join("\n- ", dpts) +
                "\nFirst Seen " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nThreat Level: " + threatLevel + " " + "|" + threatRisk + "|"+
                "\n/////////////////////////";
    }
}
