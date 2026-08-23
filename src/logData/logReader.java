package logData;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class logReader { // takes .logData.log files and txt files
    public static List<log> fileReader(String filename) throws IOException {
        List<log> logs = new ArrayList<>(); // List of logs
        List<String> rawLogs = Files.readAllLines(Path.of("logs", filename)); // Each line in the logData.log becomes a raw logData.log string in the list
        Integer count = 0;
        for (String rawLog : rawLogs){ // Goes through every raw string logData.log
            logs.add(new log(rawLog)); // Converts it to a logData.log object and adds it to the logs list
        }
        return logs;
    }
}
