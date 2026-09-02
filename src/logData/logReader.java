package logData;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;
import java.io.FileReader;


public class logReader { // takes .logData.log files and txt files
    public static Integer logsRead = 0;
    public static boolean endOfFile = false;
    public static List<log> fileReader(String filename) throws IOException {
        List<log> logs = new ArrayList<>(); // List of logs
        try (BufferedReader br = new BufferedReader(new FileReader(Path.of("logs", filename).toFile()))) {
            String rawLog;
            do {
                rawLog = br.readLine();
                if (rawLog == null) {
                    endOfFile = true;
                    break;
                }
                logsRead++;
                logs.add(new log(rawLog));
            } while ((logsRead<(logsRead+5000)));
        } catch (IOException e) {
            throw new IOException("Cannot find file under: " + filename);
        }
        return logs;
    }
}
