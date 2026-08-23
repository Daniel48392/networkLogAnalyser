package logActivityAnalysis;
import logActivityAnalysis.activityTrackers.bruteForceTracker;
import logActivityAnalysis.activityTrackers.passwordSprayTracker;
import logData.log;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class activityAnalyser {

    public static List<bruteForceTracker> bruteForceDetector(List<log> collectionLog){
        record BruteForceKey (String src, String dst){} // Key used in bruteSuspect hashmap
        HashMap<BruteForceKey, bruteForceTracker> bruteSuspect = new HashMap<>(); // Brute Force key with the bruteForeTracker class
        for (log log : collectionLog) { // For every logData.log in the collection
            if (!(log.getDuser() == null)) { // if the logData.log contains a destination user
                BruteForceKey key = new BruteForceKey(log.getSrc(), log.getDuser()); // Creates key out of source IP and destination user
                if (bruteSuspect.containsKey(key)) { // If the hashmap contains the Record key in the key value
                    bruteForceTracker tracker = bruteSuspect.get(key); // finds the bruteForceTracker object using the key
                    tracker.counterIncrement(log.getRt()); // Increments attempts by 1
                    bruteForceTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                } else {
                    bruteForceTracker tracker = new bruteForceTracker(log.getSrc(), log.getDuser(), log.getRt());
                    bruteSuspect.put(key, tracker); // Creates new bruteForceTracker and adds it with the key to the bruteSuspect hashmap
                    bruteForceTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                }
            }
        }
        List<bruteForceTracker> threats = new ArrayList<>();
        for (bruteForceTracker tracker : bruteSuspect.values()) { // for every bruteForceTracker in the hashmap
            if (tracker.getCounter() > 10) {
                threats.add(tracker); // Filters out attacks with more than 10 attempts
            }
        }
        return threats;
    }


    public static List<passwordSprayTracker> passwordSprayDetector(List<log> collectionLog){
        record sprayKey(String src, String dst){}
        HashMap<String, passwordSprayTracker> spraySuspect = new HashMap<>();
        for (log log : collectionLog) {
            if (!(log.getDuser() == null)) {
                String key = log.getSrc();
                if (spraySuspect.containsKey(key)) {
                    passwordSprayTracker tracker = spraySuspect.get(key);
                    tracker.passwordSprayAttempt(log.getDuser()); // Increments attempts by 1
                    passwordSprayTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                } else {
                    passwordSprayTracker tracker = new passwordSprayTracker(log.getSrc(), log.getDst(), log.getSuser(), log.getDuser());
                    spraySuspect.put(key, tracker);
                    passwordSprayTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                }
            }
        }
        List<passwordSprayTracker> threats = new ArrayList<>();
        for (passwordSprayTracker tracker : spraySuspect.values()) {
            if (tracker.getNumberOfUniqueAccounts() > 5) {
                threats.add(tracker);
            }
        }
        return threats;
    }



    // Password spraying multiple duser from the same IP address
    // Port scanning multiple ports being denied to the same IP from the same IP
    // DDOS multiple of the similar logs
    // SQL or injection attempts






}
