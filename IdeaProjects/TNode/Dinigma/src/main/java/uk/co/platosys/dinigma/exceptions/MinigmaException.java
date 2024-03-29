/*
 * Copyright Edward Barrow and Platosys.
 * This software is licensed under the Free Software Foundation's
General Public Licence, version 2 ("the GPL").
The full terms of the licence can be found online at http://www.fsf.org/

In brief, you are free to copy and to modify the code in any way you wish, but if you
publish the modified code you may only do so under the GPL, and (if asked) you must
 supply a copy of the source code alongside any compiled code.

Platosys software can also be licensed on negotiated terms if the GPL is inappropriate.
For further information about this, please contact software.licensing@platosys.co.uk
 */
package uk.co.platosys.dinigma.exceptions;

/**
 * @author edward
 *
 * 
 */
public class MinigmaException extends Exception {
	private static final long serialVersionUID = 4942928619188028610L;
	public MinigmaException(String msg){
		super(msg);
	}
    public MinigmaException(String msg, Throwable cause){
        super(msg, cause);
    }
}
