import logActivityAnalysis.activityTrackers.*;
import logData.logCollection;
import logData.logReader;

import java.io.IOException;

/**
 * Main class holds the main method that runs the program
 */
public class Main {
    /**
     * calls logCollection class's organiseLogs method and passes the filename in, then gets the results
     * from the static attributes of logCollection the outputs all results to the terminal
     * @param args
     * @throws IOException - filename not found
     */
    public static void main (String[] args) throws IOException {
        logCollection.organiseLogs("test_logs_v2.cef");

        System.out.println("Brute Force:");
        for (bruteForceTracker tracker : logCollection.bruteForceThreats){
            System.out.println(tracker);
        }
        System.out.println("Password Spray");
        for (passwordSprayTracker tracker : logCollection.passwordSprayThreats){
            System.out.println(tracker);
        }
        System.out.println("Vertical Port Scan");
        for (portScanVerticalTracker tracker : logCollection.portScanVerticalThreats){
            System.out.println(tracker);
        }
        System.out.println("Horizontal Port Scan");
        for (portScanHorizontalTracker tracker : logCollection.portScanHorizontalThreats){
            System.out.println(tracker);
        }
        System.out.println("Denial Of Service");
        for (denialOfServiceTracker tracker : logCollection.denialOfServiceThreatsFiltered){
            System.out.println(tracker);
        }
        System.out.println("SQL Injection");
        for (injectionSQLTracker tracker : logCollection.injectionThreats){
            System.out.println(tracker);
        }
    }
}
