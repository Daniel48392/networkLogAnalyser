package logActivityAnalysis.activityTrackers;
import java.util.ArrayList;
import java.util.List;

public class passwordSprayTracker {
    private String src;
    private String dst;
    private String suser;
    private List<String> duser = new ArrayList<String>();
    private Integer numberOfUniqueAccounts = 0;
    private Integer FailedAttempts = 0;
    private Integer SuccesfulAttempts = 0;
    private Integer UnknownAttempts = 0;

    public passwordSprayTracker(String src, String dst, String suser, String duser) {
        this.src = src;
        this.dst = dst;
        this.suser = suser;
        this.duser.add(duser);
        this.numberOfUniqueAccounts +=1;
    }

    public void passwordSprayAttempt(String duser){
        if (!(this.duser.contains(duser))) {
            this.duser.add(duser);
            this.numberOfUniqueAccounts +=1;
        }
    }

    public static void attemptCheck(passwordSprayTracker tracker, String eventReadable, String msg, String act){
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

    public Integer getNumberOfUniqueAccounts() {
        return numberOfUniqueAccounts;
    }

    @Override
    public String toString() {
        return "/////////////////////////" + "\nSource IP: " + src +
                "\nDestination IP: " + dst +
                "\nSource User: " + suser +
                "\nAccounts Targeted: " + numberOfUniqueAccounts +
                "\nTargeted Accounts:\n- " + String.join("\n- ", duser) +
                "\nFailed: " + FailedAttempts +
                "\nSuccessful: " + SuccesfulAttempts +
                "\nUnknown: " + UnknownAttempts +
                "\n/////////////////////////";
    }
}
