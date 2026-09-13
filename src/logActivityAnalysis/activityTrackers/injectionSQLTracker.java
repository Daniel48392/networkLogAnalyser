package logActivityAnalysis.activityTrackers;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class injectionSQLTracker extends tracker{
    private String dpt;
    private String dst;
    private final Instant firstSeen;
    private Instant lastSeen;
    private List<String> rawLogs = new ArrayList<String>();


    public injectionSQLTracker(String rawLog, String src, String dpt, String dst, Instant firstSeen){
        this.src = src;
        this.dpt = dpt;
        this.dst = dst;
        this.count+=1;
        this.firstSeen = firstSeen;
        this.lastSeen = firstSeen;
        this.rawLogs.add(rawLog);
    }

    public void injectionAttempt(String rawLog, Instant lastSeen){
        this.lastSeen = lastSeen;
        this.count+=1;
        this.rawLogs.add(rawLog);
    }

    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nTargeted Address: " + dst +
                "\nTargeted Port: " + dpt +
                "\nNumber of Injections: " + count +
                "\nRaw Logs:\n- " + String.join("\n- ", rawLogs) +
                "\nFirst Seen " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nThreat Level: " + threatLevel + " " + "|" + threatRisk + "|"+
                "\n/////////////////////////";
    }
}
