package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class denialOfServiceTracker extends tracker{
    private List<String> dsts = new ArrayList<>();
    private final Instant firstSeen;
    private Instant lastSeen;


    public denialOfServiceTracker(String src, String dst, Instant firstSeen) {
        this.src = src;
        if (!(dst==null) && (!(dsts.contains(dst)))){
            this.dsts.add(dst);
        }
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
        count+=1;
    }

    public void counterIncrement(String dst, Instant timestamp){
        if (!(dst==null) && (!(dsts.contains(dst)))){
            this.dsts.add(dst);
        }
        count+=1;
        lastSeen = timestamp;
    }


    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nFirst Seen: " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nAttempts: " + count +
                "\nTargeted Addresses: \n-" + String.join("\n- ", dsts) +
                "\nThreat Level: " + threatLevel + " " + "|" + threatRisk + "|"+
                "\n/////////////////////////";
    }
}
