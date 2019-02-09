/*
 * BetterCipher.java
 * 
 * @author Juan Arias
 * 
 */

package Assignment1;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.BitSet;

/*
 * Implementing improvements measured by avalanche effect
 */
public class BetterCipher extends WeakCipher {
	
	/*
	 * Pass amount of plaintexts, keys and sboxes to superclass
	 */
	public BetterCipher(int plaintexts, int keys, int sboxes) {
		super(plaintexts, keys, sboxes);
	}
	
	/*
	 * Construct better cipher from weak one
	 */
	public BetterCipher(WeakCipher weak) {
		super(weak.plaintexts.length, weak.keys.length, weak.sboxes.length);
		copy(weak);
	}
	
	/*
	 * Write the ciphertext outputs to a file
	 */
	@Override
	public void write(String filename) throws IOException {
		PrintWriter writer = new PrintWriter(
							 new BufferedWriter(
							 new FileWriter(filename, true)));
		writer.println();
		writer.print("BetterCipher: ");
		writeAvalancheEffect(writer);
		writer.close();
	}
	
	/*
	 * Become deep copy of weaker cipher
	 */
	private void copy(WeakCipher weak) {
		copy(this.plaintexts, weak.plaintexts);
		copy(this.keys, weak.keys);
		for (int i = 0; i < sboxes.length; ++i) {
			copy(sboxes[i], weak.sboxes[i]);
		}
	}
	
	/*
	 * Copy matrix2 into matrix1
	 */
	private static void copy(BitSet[][] matrix1, BitSet[][] matrix2) {
		for (int i = 0; i < matrix1.length; ++i) {
			matrix1[i] = matrix2[i].clone();
		}
	}
	
	/*
	 * Enhanced encryption overload
	 */
	@Override
	protected BitSet[] encrypt(BitSet[] plaintext, BitSet[] key) {
		BitSet[] ciphertext = super.encrypt(plaintext, key);
		ciphertext = super.encrypt(plaintext, ciphertext);
		return rounds(ciphertext, key.clone(), 5);
	}
	
	/*
	 * Transformations by rounds
	 */
	private BitSet[] rounds(BitSet[] ciphertext, BitSet[] key, int rounds) {
		for (int i = 0; i < rounds; ++i) {
			extraEncrypt(ciphertext);
			leftShift(key);
			ciphertext = super.encrypt(ciphertext, key);
		}
		return ciphertext;
	}
	
	/*
	 * Encryption enhancement for each ciphertext
	 */
	private void extraEncrypt(BitSet[] ciphertext) {
		for (int i = 0; i < BLOCK_SZ; ++i) {
			xorSubs(ciphertext[i]);
			ciphertext[i] = subsub(ciphertext[i]);
			xorSubs(ciphertext[i]);
		}
		leftShift(ciphertext);
	}
	
	/*
	 * XOR block with its subs from each sbox
	 */
	private void xorSubs(BitSet block) {
		BitSet xorBlock;
		for (int i = 0; i < sboxes.length; ++i) {
			xorBlock = sub(block, i);
			block.xor(xorBlock);
		}
	}
	
	/*
	 * Substitute block many times
	 */
	private BitSet subsub(BitSet block) {
		block = sub(sub(block, 1), 0);
		block = sub(sub(block, 0), 1);
		block = sub(sub(block, 0), 0);
		return sub(sub(block, 1), 1);
	}
	
	/*
	 * Left circular shift
	 */
	private void leftShift(BitSet[] ciphertext) {
		BitSet firstBlock = ciphertext[0];
		for (int i = 0; i < BLOCK_SZ - 1; ++i) {
			ciphertext[i] = ciphertext[i + 1];
		}
		ciphertext[BLOCK_SZ - 1] = firstBlock;
	}
}







