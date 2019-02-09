/*
 * Main.java
 * 
 * @author Juan Arias
 * 
 */

package Assignment1;

import java.io.IOException;

/*
 * Testing
 */
public class Main {
	
	/*
	 * Tests
	 */
	public static void main(String[] args) throws IOException {
		WeakCipher weak = new WeakCipher(1, 1, 2);
		weak.read("example.txt");
		weak.write("example.txt");
		weak = new WeakCipher(5, 2, 2);
		weak.read("assignment1.txt");
		weak.write("assignment1.txt");
		BetterCipher better = new BetterCipher(weak);
		better.write("assignment1.txt");
	}
}
