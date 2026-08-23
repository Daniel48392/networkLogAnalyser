package logData;

public class logExtensionParser {
    /**
     *
     * @param rawExtensions
     * @param extension
     * @return
     */
    public static int spaceFinder(String rawExtensions, String extension){
        int length = rawExtensions.length()-1;
        int spaceFinder = rawExtensions.indexOf(" ", rawExtensions.indexOf(extension));
        if (spaceFinder == -1){
            return length;
        }
        int newSpace = spaceFinder;
        char currentChar;
        do {
            spaceFinder +=1;
            currentChar = rawExtensions.charAt(spaceFinder);
            if (currentChar == ' '){
                newSpace = spaceFinder;
            }
        }
        while (currentChar != ('=') && spaceFinder != length);
        return newSpace;
    }
}
