package logData;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;
import java.io.FileReader;

/**
 * Contains method that reads and converts the CEF files line by line
 */
public class logReader {
    public static Integer logsRead = 0; // Number of logs read
    public static Integer logsReadTarget = 5000; // Placeholder
    public static boolean endOfFile = false; // Has the read reached the end of the file

    /**
     * Iterates through the log files instantiating them into log objects one by one while incrementing the logs read counter
     * @param filename - name of the CEF log file to be read
     * @return logs - an ArrayList of Log objects that have been instantiated from the file of logs provided
     * @throws IOException - filename cannot be found
     */
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
            } while (true);
        } catch (IOException e) {
            throw new IOException("Cannot find file under: " + filename);
        }
        logsReadTarget +=5000; // Placeholder
        return logs;
    }
}
