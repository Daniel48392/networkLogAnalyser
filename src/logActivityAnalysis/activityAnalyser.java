package logActivityAnalysis;
import logActivityAnalysis.activityTrackers.*;
import logData.log;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Contains all the static methods and attributes that sort the logs into potential attacks
 */
public class activityAnalyser {
    record InjectionKey (String src, String dst){} // makes unique key for hashmap for injection attacks
    private static HashMap<InjectionKey, injectionSQLTracker> injectionSuspects = new HashMap<>(); // hashmap for injection attacks

    record BruteForceKey (String src, String dst){} // Key used in bruteSuspect hashmap
    private static HashMap<BruteForceKey, bruteForceTracker> bruteSuspect = new HashMap<>(); // Brute Force key with the bruteForeTracker class

    private static HashMap<String, passwordSprayTracker> spraySuspect = new HashMap<>(); // hashmap for password spray attacks


    record verticalPortScanKey (String src, String dst){} // creates unique key for vertical port scan attacks and is used in the vertical port scan attacks hashmap
    private static HashMap<verticalPortScanKey, portScanVerticalTracker> verticalScanSuspect = new HashMap<>(); // hashmap for vertical port scans

    record horizontalPortScanKey(String src, String dport){} // creates unique key for horizontal port scan attacks and is used in the horizontal port scan attacks hashmap
    private static HashMap<horizontalPortScanKey, portScanHorizontalTracker> horizontalScanSuspect = new HashMap<>(); // hashmap for horizontal port scans


    private static HashMap<String, denialOfServiceTracker> denialOfServiceSuspect = new HashMap<>(); // hashmap for denial of service attacks

    /**
     * Iterates through each log and checks if the Injection value is true then adds it as a tracker to the hashmap
     * or increments an existing tracker
     * <p>
     *     Checks if getInjection is true, then creates the key out of the logs attributes, if the hashmap already contains the
     *     key the tracker value matching that key is returned from the hashmap and then .injectionAttempt is run and the logs
     *     information is passed into the tracker, if it is new the log instead gets instantiated into a injectionSQLTracker object and added
     *     to the hashmap with its key
     * </p>
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void injection_SQL_Detection(List<log> collectionLog){
        for (log log : collectionLog) {
            if (log.getInjection()){
                InjectionKey key = new InjectionKey(log.getSrc(), log.getDst());
                if (injectionSuspects.containsKey(key)){
                    injectionSQLTracker tracker = injectionSuspects.get(key);
                    tracker.injectionAttempt(log.getRawLog(), log.getRt());
                } else {
                    injectionSQLTracker tracker = new injectionSQLTracker(log.getRawLog(), log.getSrc(), log.getDpt(), log.getDst(), log.getRt());
                    injectionSuspects.put(key, tracker);
                }
            }
        }
    }

    /**
     * Returns an ArrayList of all the values in the injectionSuspects hashmap
     * @return ArrayList of all the values in the injectionSuspects hashmap
     */
    public static List<injectionSQLTracker> getInjectionThreats(){
        return new ArrayList<>(injectionSuspects.values());
    }


    /**
     * Iterates through each log and checks if the suser or duser isn't null then adds it as a tracker to the hashmap
     * or increments an existing tracker
     * <p>
     *     Iterates through the logs checking that the logs aren't injection attacks and contain either suser or duser,
     *     if they do a key is then made and the hashmap gets checked if that key exists in it, if it does the tracker using that
     *     key in the hashmap is then incremented using the values from the current log, otherwise if it's new the log gets
     *     a bruteForceTracker instantiated from. With every log that is added to the hashmap either through incrementation
     *     or instantiation attemptCheck is always ran.
     * </p>
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void bruteForceDetector(List<log> collectionLog){
        for (log log : collectionLog) { // For every logData.log in the collection
            if (!(log.getDuser() == null) && !log.getInjection()) { // if the logData.log contains a destination user
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
            else if (!(log.getSuser() == null) && !log.getInjection()) {
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

    /**
     * Creates an array list for brute force trackers, each value from the hashmap is iterated through, if the
     * bruteForceTracker contains more than 8 attempts it gets added to the list of threats
     * @return arrayList of bruteForceTracker threats
     */
    public static List<bruteForceTracker> getBruteForceThreats(){
        List<bruteForceTracker> threats = new ArrayList<>();
        for (bruteForceTracker tracker : bruteSuspect.values()) { // for every bruteForceTracker in the hashmap
            if (tracker.getCount() > 8) {
                threats.add(tracker); // Filters out attacks with more than 8 attempts
            }
        }
        return threats;
    }


    /**
     * Iterates through each log and checks if suser or duser isn't null then adds it as a tracker to the hashmap
     * or increments an existing tracker
     * <p>
     *     Iterates through each log, checks if suser or duser isn't null, and it isn't an injection attack, then uses the
     *     source IP to create a key, if the key already exists in the hashmap the tracker under that key is retrieved from the hashmap
     *     and is incremented using the current log, otherwise a passwordSprayTracker is instantiated out of the log in both these
     *     scenarios a .attemptCheck is run on the tracker.
     * </p>
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void passwordSprayDetector(List<log> collectionLog){
        for (log log : collectionLog) {
            if (!(log.getDuser() == null) && !log.getInjection()) {
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
            else if (!(log.getSuser() == null) && !log.getInjection()) { // When Suser is the source of the attack failed logins on Suser
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

    /**
     * Creates an array list for password spray threats, each value from the hashmap is iterated through, if the
     * passwordSprayTracker contains more than 8 attempts it gets added to the list of threats
     * @return arrayList of passwordSpray threats
     */
    public static List<passwordSprayTracker> getPasswordSprayThreats(){
        List<passwordSprayTracker> threats = new ArrayList<>();
        for (passwordSprayTracker tracker : spraySuspect.values()) {
            if (tracker.getCount() > 8) {
                threats.add(tracker);
            }
        }
        return threats;
    }

    /**
     *
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void portScanVerticalDetector(List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getDpt() == null) && !log.getInjection()) {
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


    /**
     *
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void portScanHorizontalDetector(List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getDst() == null)&&!(log.getDpt() == null) && !log.getInjection()) {
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

    /**
     *
     * @param collectionLog - all the log objects instantiated from the CEF source file
     */
    public static void denialOfServiceDetector (List<log> collectionLog){
        for  (log log : collectionLog) {
            if (!(log.getSrc() == null)&&!(log.getDpt() == null) && !log.getInjection()) {
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
}
