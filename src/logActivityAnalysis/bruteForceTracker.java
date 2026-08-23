package logActivityAnalysis;
import java.time.Instant;


public class bruteForceTracker {
    private String src; // Source IP
    private String duser; // Destination user
    private Instant firstSeen; // First occurrence
    private Instant lastSeen; // Last occurrence
    private Integer counter = 0; // Number of detections
    private Integer FailedAttempts = 0;
    private Integer SuccesfulAttempts = 0;
    private Integer UnknownAttempts = 0;

    public bruteForceTracker(String src, String duser, Instant timestamp){
        this.src = src;
        this.duser = duser;
        firstSeen = timestamp;
        lastSeen = timestamp;
        counter +=1;
    }

    public void counterIncrement(Instant timestamp){
        counter+=1;
        lastSeen = timestamp;
    }

    public static void attemptCheck(bruteForceTracker tracker, String eventReadable, String msg, String act){
        if (!(eventReadable == null)) {
            if (eventReadable.toLowerCase().contains("fail") || eventReadable.toLowerCase().contains("invalid") || eventReadable.toLowerCase().contains("incorrect") || eventReadable.toLowerCase().contains("denied")) {
                tracker.FailedAttempts++;
            } else if (eventReadable.toLowerCase().contains("success") || eventReadable.toLowerCase().contains("valid") || eventReadable.toLowerCase().contains("grant")) {
                tracker.SuccesfulAttempts++;
            }
            else  {
                tracker.UnknownAttempts++;
            }
        }
        else if (!(msg == null)) {
            if (msg.toLowerCase().contains("fail") || msg.toLowerCase().contains("invalid") || msg.toLowerCase().contains("incorrect") || msg.toLowerCase().contains("denied")) {
                tracker.FailedAttempts++;
            } else if (msg.toLowerCase().contains("success") || msg.toLowerCase().contains("valid") || msg.toLowerCase().contains("grant")) {
                tracker.SuccesfulAttempts++;
            }
            else  {
                tracker.UnknownAttempts++;
            }
        }
        else if (!(act == null)) {
            if (act.toLowerCase().contains("fail") || act.toLowerCase().contains("denied")) {
                tracker.FailedAttempts++;
            } else if (act.toLowerCase().contains("success") || act.toLowerCase().contains("allow") || eventReadable.toLowerCase().contains("login") || eventReadable.toLowerCase().contains("authenticated")) {
                tracker.SuccesfulAttempts++;
            }
            else  {
                tracker.UnknownAttempts++;
            }
        }
        else {
            tracker.UnknownAttempts++;
        }
    }


    public Integer getCounter() {
        return counter;
    }

    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nTarget User: " + duser +
                "\nFirst Seen: " + firstSeen +
                "\nLast Seen: " + lastSeen +
                "\nAttempts: " + counter +
                "\nFailed: " + FailedAttempts +
                "\nSuccessful: " + SuccesfulAttempts +
                "\nUnknown: " + UnknownAttempts +
                "\n/////////////////////////";
    }
}
