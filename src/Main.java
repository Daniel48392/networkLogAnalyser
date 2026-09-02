import logActivityAnalysis.activityTrackers.*;
import logData.logCollection;
import logData.logReader;

import java.io.IOException;

// test
public class Main {
    public static void main (String[] args) throws IOException {
        logCollection.organiseLogs("test_logs.cef");

        System.out.println("Brute Force:");
        for (bruteForceTracker tracker : logCollection.bruteForceThreats){
            System.out.println(tracker); // Working
        }
        System.out.println("Password Spray");
        for (passwordSprayTracker tracker : logCollection.passwordSprayThreats){
            System.out.println(tracker); // Working
        }
        System.out.println("Vertical Port Scan");
        for (portScanVerticalTracker tracker : logCollection.portScanVerticalThreats){
            System.out.println(tracker); // Working
        }
        System.out.println("Horizontal Port Scan");
        for (portScanHorizontalTracker tracker : logCollection.portScanHorizontalThreats){
            System.out.println(tracker); // Working
        }
        System.out.println("Denial Of Service");
        for (denialOfServiceTracker tracker : logCollection.denialOfServiceThreats){
            System.out.println(tracker);
        }

    }
}
