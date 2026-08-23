package logData;

import logActivityAnalysis.activityAnalyser;
import logActivityAnalysis.bruteForceTracker;

import java.io.IOException;
import java.nio.file.Path;
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
    }

}
