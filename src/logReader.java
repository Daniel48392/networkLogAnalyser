import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class logReader {
    // takes .log files and txt files CHECK CHECK FIRST DRAFT NOT TESTED properly
    public static List<log> fileReader(String filename) throws IOException {
        List<log> logs = new ArrayList<>();
        File rawLog2s = new File(filename);
        List<String> rawLogs = Files.readAllLines(Path.of("logs", filename));
        for (String rawLog : rawLogs){
            logs.add(new log(rawLog));
        }
        return logs;
    }
}
