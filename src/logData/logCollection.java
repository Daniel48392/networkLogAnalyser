package logData;
import logActivityAnalysis.activityAnalyser;
import logActivityAnalysis.activityTrackers.*;

import java.io.IOException;
import java.util.List;

public class logCollection {
    private static List<log> collectionLogs;
    // contains all instantiated logs
    public static void main(String[] args) throws IOException {
        collectionLogs = logReader.fileReader("moreCEF.log");
        List<bruteForceTracker> bruteForceThreats = activityAnalyser.bruteForceDetector(collectionLogs);
        System.out.println("Highest Risk Brute Force Threats: ");
        for (bruteForceTracker tracker : bruteForceThreats) {
            System.out.println(tracker.toString());
        }
        List<passwordSprayTracker> passwordSprayThreats = activityAnalyser.passwordSprayDetector(collectionLogs);
        System.out.println("Highest Risk Password Spray Threats: ");
        for (passwordSprayTracker tracker : passwordSprayThreats){
            System.out.println(tracker.toString());
        }
        List<portScanVerticalTracker>  portScanVerticalThreats = activityAnalyser.portScanVerticalDetector(collectionLogs);
        System.out.println("Highest Risk Vertical Port Scan Threats: ");
        for (portScanVerticalTracker tracker : portScanVerticalThreats){
            System.out.println(tracker.toString());
        }
        List<portScanHorizontalTracker> portScanHorizontalThreats = activityAnalyser.portScanHorizontalDetector(collectionLogs);
        System.out.println("Highest Risk Horizontal Port Scan Threats: ");
        for (portScanHorizontalTracker tracker : portScanHorizontalThreats){
            System.out.println(tracker.toString());
        }
        List<denialOfServiceTracker> denialOfServiceThreats = activityAnalyser.denialOfServiceDetector(collectionLogs);
        System.out.println("Highest Risk Denial Of Service Threats: ");
        for (denialOfServiceTracker tracker : denialOfServiceThreats){
            System.out.println(tracker.toString());
        }
    }


}
