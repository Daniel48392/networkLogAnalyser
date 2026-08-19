import java.io.IOException;

public class logCollection {
    // contains all instantiated logs
    public static void main(String[] args) throws IOException {
        System.out.println(logReader.fileReader("network_cef_logs.log"));
    }

}
