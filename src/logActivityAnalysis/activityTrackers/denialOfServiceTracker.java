package logActivityAnalysis.activityTrackers;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class denialOfServiceTracker extends tracker{
    private List<String> dsts = new ArrayList<>();
    private final Instant firstSeen;
    private Instant lastSeen;
    private Integer counter = 0;

    public denialOfServiceTracker(String src, String dst, Instant firstSeen) {
        this.src = src;
        if (!(dst==null) && (!(dsts.contains(dst)))){
            this.dsts.add(dst);
        }
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
        counter+=1;
    }

    public void counterIncrement(String dst, Instant timestamp){
        if (!(dst==null) && (!(dsts.contains(dst)))){
            this.dsts.add(dst);
        }
        counter+=1;
        lastSeen = timestamp;
    }

    public Integer getCounter() {
        return counter;
    }

    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nFirst Seen: " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nAttempts: " + counter +
                "\nTargeted Addresses: \n-" + String.join("\n- ", dsts) +
                "\n/////////////////////////";
    }
}
