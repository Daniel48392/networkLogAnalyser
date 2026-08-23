import logData.logReader;

import java.io.IOException;

// test
public class Main {
    public static void main (String[] args) throws IOException {
        System.out.println(logReader.fileReader("cef_samples.txt"));
    }
}
