package uk.co.platosys.minigma.exceptions;

public class Exceptions {

    public static void dump (Throwable e) {
        System.out.println(e.getClass().getName() + ":" + e.getMessage());
        if (e.getCause() != null) {
            dump(e.getCause());
        } else {
            StackTraceElement[] stackTraceElements = e.getStackTrace();
            for (StackTraceElement stackTraceElement : stackTraceElements) {
                System.out.println(stackTraceElement.toString());
            }
        }
    }
}
