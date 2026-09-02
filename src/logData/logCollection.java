package logData;
import logActivityAnalysis.activityAnalyser;
import logActivityAnalysis.activityTrackers.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class logCollection {
    private static List<log> collectionLogs = new ArrayList<>();
    public static List<bruteForceTracker> bruteForceThreats = new ArrayList<>();
    public static List<passwordSprayTracker> passwordSprayThreats = new ArrayList<>();
    public static List<portScanVerticalTracker>  portScanVerticalThreats = new ArrayList<>();
    public static List<portScanHorizontalTracker>  portScanHorizontalThreats =  new ArrayList<>();
    public static List<denialOfServiceTracker> denialOfServiceThreats = new ArrayList<>();

    // contains all instantiated logs
    public static void organiseLogs(String filename) throws IOException {

        while(logReader.endOfFile != true){
            collectionLogs.addAll(logReader.fileReader(filename));
            activityAnalyser.bruteForceDetector(collectionLogs);
            activityAnalyser.passwordSprayDetector(collectionLogs);
            activityAnalyser.portScanVerticalDetector(collectionLogs);
            activityAnalyser.portScanHorizontalDetector(collectionLogs);
            activityAnalyser.denialOfServiceDetector(collectionLogs);
        }

        bruteForceThreats = activityAnalyser.getBruteForceThreats();
        passwordSprayThreats = activityAnalyser.getPasswordSprayThreats();
        portScanVerticalThreats = activityAnalyser.getPortScanVerticalThreats();
        portScanHorizontalThreats = activityAnalyser.getPortScanHorizontalThreats();
        denialOfServiceThreats = activityAnalyser.getDenialOfServiceThreats();


        for (bruteForceTracker threat : bruteForceThreats){ // Repeat for others
            threat.setThreat();
        }
        for (passwordSprayTracker threat : passwordSprayThreats){
            threat.setThreat();
        }
        for (portScanVerticalTracker threat : portScanVerticalThreats){
            threat.setThreat();
        }
        for (portScanHorizontalTracker threat : portScanHorizontalThreats){
            threat.setThreat();
        }
        for (denialOfServiceTracker threat : denialOfServiceThreats){
            threat.setThreat();
        }






    }
}
