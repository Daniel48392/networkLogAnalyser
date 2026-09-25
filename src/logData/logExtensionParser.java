package logData;

/**
 * Contains method that works with the extension of a CEF log
 */
public class logExtensionParser {
    /**
     * Finds the ending boundary of a value in the extension field
     * <p>
     *     Finds the ending boundary by finding the first space using indexOf but because some of the values in the
     *     extension field have spaces in them, it checks there are no spaces until it reaches the = sign of the next value
     *     in the extensions field, however if it is the last value in the extensions field it returns the last index of the
     *     extensions field.
     * </p>
     * @param rawExtensions - part of the raw CEF log that isn't mandatory and can vary
     * @param extension - the name of the field in the extension your looking trying to get the value of, for example 'suser=' for source user
     * @return newSpace - the index of the where your target value in the extension ends
     * @return length - when the target value is the last value in the extension
     */
    public static int spaceFinder(String rawExtensions, String extension){
        int length = rawExtensions.length()-1;
        int spaceFinder = rawExtensions.indexOf(" ", rawExtensions.indexOf(extension));
        if (spaceFinder == -1){ // Last value in the extension
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
        while (currentChar != ('=') && spaceFinder != length); //TODO Could cause issues where a extension value contains a space then an equals sign in it
        return newSpace;
    }
}
