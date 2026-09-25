package logData;
import logActivityAnalysis.activityAnalyser;
import logActivityAnalysis.activityTrackers.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * logCollection class where all the logs are sorted and stored
 */
public class logCollection {
    private static List<log> collectionLogs = new ArrayList<>();

    public static List<injectionSQLTracker> injectionThreats = new ArrayList<>();
    public static List<bruteForceTracker> bruteForceThreats = new ArrayList<>();
    public static List<passwordSprayTracker> passwordSprayThreats = new ArrayList<>();
    public static List<portScanVerticalTracker>  portScanVerticalThreats = new ArrayList<>();
    public static List<portScanHorizontalTracker>  portScanHorizontalThreats =  new ArrayList<>();
    public static List<denialOfServiceTracker> denialOfServiceThreats = new ArrayList<>();
    public static List<denialOfServiceTracker> denialOfServiceThreatsFiltered = new ArrayList<>();


    public static List<String> attackIPs  = new ArrayList<>();
    // contains all instantiated logs

    /**
     * organizes the CEF logs into lists of threats
     * <p>
     *     Uses the logReader class to convert all the CEF text into log classes which then get passed
     *     into the collectionLogs.
     *     Then it calls methods in the activityAnalyser class to organize the logs into threats.
     *     The collectionLogs class attributes which are the lists of each type of threat then get assigned what
     *     the activityAnalyser's methods determined could be potential threats the logs are now converted to trackers
     *     specific to each attack.
     *     The method then sets the threat level for the new Tracker objects and then filters out the IP addresses from
     *     previous threats so that every already defined threat is not also defined as a DOS attack.
     * </p>
     * @param filename - name of file containing CEF logs
     * @throws IOException - filename cannot be found
     */
    public static void organiseLogs(String filename) throws IOException {

        collectionLogs.addAll(logReader.fileReader(filename));
        activityAnalyser.injection_SQL_Detection(collectionLogs);
        activityAnalyser.bruteForceDetector(collectionLogs);
        activityAnalyser.passwordSprayDetector(collectionLogs);
        activityAnalyser.portScanVerticalDetector(collectionLogs);
        activityAnalyser.portScanHorizontalDetector(collectionLogs);
        activityAnalyser.denialOfServiceDetector(collectionLogs);
        collectionLogs.clear();


        injectionThreats = activityAnalyser.getInjectionThreats();
        bruteForceThreats = activityAnalyser.getBruteForceThreats();
        passwordSprayThreats = activityAnalyser.getPasswordSprayThreats();
        portScanVerticalThreats = activityAnalyser.getPortScanVerticalThreats();
        portScanHorizontalThreats = activityAnalyser.getPortScanHorizontalThreats();
        denialOfServiceThreats = activityAnalyser.getDenialOfServiceThreats();

        for (bruteForceTracker threat : bruteForceThreats){ // Repeat for others
            threat.setThreat();
            attackIPs.add(threat.getSrc());
        }
        for (passwordSprayTracker threat : passwordSprayThreats){
            threat.setThreat();
            attackIPs.add(threat.getSrc());
        }
        for (portScanVerticalTracker threat : portScanVerticalThreats){
            threat.setThreat();
            attackIPs.add(threat.getSrc());
        }
        for (portScanHorizontalTracker threat : portScanHorizontalThreats){
            threat.setThreat();
            attackIPs.add(threat.getSrc());
        }


        for (injectionSQLTracker threat : injectionThreats){
            threat.setThreat();
        }


        for (denialOfServiceTracker threat : denialOfServiceThreats){
            threat.setThreat();
            if (!(attackIPs.contains(threat.getSrc()))){
                denialOfServiceThreatsFiltered.add(threat);
            }
        }






    }
}
