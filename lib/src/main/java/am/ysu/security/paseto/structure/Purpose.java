package am.ysu.security.paseto.structure;

public enum Purpose {
    PUBLIC("public"),
    LOCAL("local");

    private final String encodedValue;

    Purpose(String encodedValue) {
        this.encodedValue = encodedValue;
    }

    public static Purpose of(String purpose) {
        for(Purpose aPurpose : Purpose.values()) {
            if(aPurpose.encodedValue.equalsIgnoreCase(purpose)) {
                return aPurpose;
            }
        }
        throw new IllegalArgumentException("Unknown purpose " + purpose);
    }
}
