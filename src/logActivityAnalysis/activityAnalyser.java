package logActivityAnalysis;
import logActivityAnalysis.activityTrackers.bruteForceTracker;
import logActivityAnalysis.activityTrackers.passwordSprayTracker;
import logActivityAnalysis.activityTrackers.portScanHorizontalTracker;
import logActivityAnalysis.activityTrackers.portScanVerticalTracker;
import logActivityAnalysis.activityTrackers.denialOfServiceTracker;
import logData.log;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class activityAnalyser {
    record BruteForceKey (String src, String dst){} // Key used in bruteSuspect hashmap
    private static HashMap<BruteForceKey, bruteForceTracker> bruteSuspect = new HashMap<>(); // Brute Force key with the bruteForeTracker class

    private static HashMap<String, passwordSprayTracker> spraySuspect = new HashMap<>();


    record verticalPortScanKey (String src, String dst){}
    private static HashMap<verticalPortScanKey, portScanVerticalTracker> verticalScanSuspect = new HashMap<>();

    record horizontalPortScanKey(String src, String dport){}
    private static HashMap<horizontalPortScanKey, portScanHorizontalTracker> horizontalScanSuspect = new HashMap<>();


    private static HashMap<String, denialOfServiceTracker> denialOfServiceSuspect = new HashMap<>();

    public static void bruteForceDetector(List<log> collectionLog){
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
            else if (!(log.getSuser() == null)) {
                BruteForceKey key = new BruteForceKey(log.getSrc(), log.getSuser()); // Creates key out of source IP and destination user
                if (bruteSuspect.containsKey(key)) { // If the hashmap contains the Record key in the key value
                    bruteForceTracker tracker = bruteSuspect.get(key); // finds the bruteForceTracker object using the key
                    tracker.counterIncrement(log.getRt()); // Increments attempts by 1
                    bruteForceTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                } else {
                    bruteForceTracker tracker = new bruteForceTracker(log.getSrc(), log.getSuser(), log.getRt());
                    bruteSuspect.put(key, tracker); // Creates new bruteForceTracker and adds it with the key to the bruteSuspect hashmap
                    bruteForceTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                }
            }
        }
        bruteSuspect.keySet().removeIf(key -> bruteSuspect.get(key).getCount() < 3);
    }


    public static List<bruteForceTracker> getBruteForceThreats(){
        List<bruteForceTracker> threats = new ArrayList<>();
        for (bruteForceTracker tracker : bruteSuspect.values()) { // for every bruteForceTracker in the hashmap
            if (tracker.getCount() > 8) {
                threats.add(tracker); // Filters out attacks with more than 10 attempts
            }
        }
        return threats;
    }





    public static void passwordSprayDetector(List<log> collectionLog){
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
            else if (!(log.getSuser() == null)) { // When Suser is the source of the attack failed logins on Suser
                String key = log.getSrc();
                if (spraySuspect.containsKey(key)) {
                    passwordSprayTracker tracker = spraySuspect.get(key);
                    tracker.passwordSprayAttempt(log.getSuser()); // Increments attempts by 1
                    passwordSprayTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                } else {
                    passwordSprayTracker tracker = new passwordSprayTracker(log.getSrc(), log.getDst(), null, log.getSuser());
                    spraySuspect.put(key, tracker);
                    passwordSprayTracker.attemptCheck(tracker, log.getEventReadable(), log.getMsg(), log.getAct());
                }
            }
        }
        spraySuspect.keySet().removeIf(key -> spraySuspect.get(key).getCount() < 3);
    }


    public static List<passwordSprayTracker> getPasswordSprayThreats(){
        List<passwordSprayTracker> threats = new ArrayList<>();
        for (passwordSprayTracker tracker : spraySuspect.values()) {
            if (tracker.getCount() > 8) {
                threats.add(tracker);
            }
        }
        return threats;
    }

    public static void portScanVerticalDetector(List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getDpt() == null)) {
                verticalPortScanKey key = new verticalPortScanKey(log.getSrc(), log.getDst());
                if (verticalScanSuspect.containsKey(key)) {
                    portScanVerticalTracker tracker = verticalScanSuspect.get(key);
                    tracker.portScanAttempt(log.getDpt(), log.getRt());
                } else {
                    portScanVerticalTracker tracker = new portScanVerticalTracker(log.getSrc(), log.getDst(), log.getDpt(), log.getRt());
                    verticalScanSuspect.put(key, tracker);
                }
            }
        }
        verticalScanSuspect.keySet().removeIf(key -> verticalScanSuspect.get(key).getCount() < 3);
    }

    public static List<portScanVerticalTracker> getPortScanVerticalThreats(){
        List<portScanVerticalTracker> threats = new ArrayList<>();
        for (portScanVerticalTracker tracker : verticalScanSuspect.values()) {
            if (tracker.getCount() > 10) {
                threats.add(tracker);
            }
        }
        return threats;
    }



    public static void portScanHorizontalDetector(List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getDst() == null)&&!(log.getDpt() == null)) {
                horizontalPortScanKey key = new horizontalPortScanKey(log.getSrc(), log.getDpt());
                if (horizontalScanSuspect.containsKey(key)) {
                    portScanHorizontalTracker tracker = horizontalScanSuspect.get(key);
                    tracker.portScanAttempt(log.getDst(), log.getRt());
                } else {
                    portScanHorizontalTracker tracker = new portScanHorizontalTracker(log.getSrc(), log.getDst(), log.getDpt(), log.getRt());
                    horizontalScanSuspect.put(key, tracker);
                }
            }
        }
        horizontalScanSuspect.keySet().removeIf(key -> horizontalScanSuspect.get(key).getCount() < 3);
    }

    public static List<portScanHorizontalTracker> getPortScanHorizontalThreats(){
        List<portScanHorizontalTracker> threats = new ArrayList<>();
        for (portScanHorizontalTracker tracker : horizontalScanSuspect.values()) {
            if (tracker.getCount() > 10) {
                threats.add(tracker);
            }
        }
        return threats;
    }


    public static void denialOfServiceDetector (List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getSrc() == null)&&!(log.getDpt() == null)) {
                String key = log.getSrc();
                if (denialOfServiceSuspect.containsKey(key)) {
                    denialOfServiceTracker tracker = denialOfServiceSuspect.get(key);
                    tracker.counterIncrement(log.getDst(), log.getRt());
                } else {
                    denialOfServiceTracker tracker = new denialOfServiceTracker(log.getSrc(), log.getDst(), log.getRt());
                    denialOfServiceSuspect.put(key, tracker);
                }
            }
        }
        denialOfServiceSuspect.keySet().removeIf(key -> denialOfServiceSuspect.get(key).getCount() < 5);
    }

    public static List<denialOfServiceTracker> getDenialOfServiceThreats(){
        List<denialOfServiceTracker> threats = new ArrayList<>();
        for (denialOfServiceTracker tracker : denialOfServiceSuspect.values()) {
            if (tracker.getCount()>15) {
                threats.add(tracker);
            }
        }
        return threats;
    }





    // DDOS multiple of the similar logs
    // SQL or injection attempts






}
