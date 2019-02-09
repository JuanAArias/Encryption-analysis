/*
 * WeakCipher.java
 * 
 * @author Juan Arias
 * 
 */

package Assignment1;

import java.util.*;
import java.io.*;

/*
 * Assignment1 WeakCipher implementation
 */
public class WeakCipher {
	
	/* Block sz in bits , index where bits start in each line in file */
	protected static final int BLOCK_SZ = 4;

	private static final int BIT_INDEX = 5;
	
	/* Bit char */
	private static final char BIT = '1', NO_BIT = '0';
	
	/* Bits changed during avalanche effect calculation */
	protected static final double CHANGED_BITS = 2560;
	
	/* Output strings */
	protected static final String OUTPUT = "c%d%d = E(p%d, k%d) = ",
			AVALANCHE = "Avalanche = %d different bits / 2560 changed bits = %.2f";
	
	/* Bits for plaintexts, keys and sboxes */
	protected BitSet[][] plaintexts, keys;
	protected BitSet[][][] sboxes;

	/*
	 * Construct cipher from file info
	 */
	public WeakCipher(int plaintexts, int keys, int sboxes) {
		this.plaintexts = new BitSet[plaintexts][BLOCK_SZ];
		this.keys 		= new BitSet[keys][BLOCK_SZ];
		this.sboxes	    = new BitSet[sboxes][BLOCK_SZ][BLOCK_SZ];
	}
	
	/*
	 * Get plaintexts, keys and sboxes from a file
	 */
	public void read(String filename) throws FileNotFoundException {
		Scanner fileScan = new Scanner(new File(filename));
		get(plaintexts, fileScan);
		get(keys, fileScan);
		for (BitSet[][] sbox : sboxes) {
			get(sbox, fileScan);
		}
		fileScan.close();
	}
	
	/*
	 * Write the ciphertext outputs to a file
	 */
	public void write(String filename) throws IOException {
		PrintWriter writer = new PrintWriter(
							 new BufferedWriter(
							 new FileWriter(filename, true)));
		BitSet[][][] ciphertexts = encrypt();
		for (int i = 0; i < ciphertexts.length; ++i) {
			writeCiphertextPerKey(ciphertexts[i], writer, i + 1);
			writer.println();
		}
		writer.println();
		writeAvalancheEffect(writer);
		writer.close();
	}
	
	/*
	 * Get bits from file
	 */
	private static void get(BitSet[][] bitMatrix, Scanner fileScan) {
		for (int i = 0; i < bitMatrix.length; ++i) {
			String line = fileScan.nextLine().substring(BIT_INDEX);
			String[] tokens = line.split(" ");
			fillBits(bitMatrix[i], tokens);
		}
		fileScan.nextLine();
	}
	
	/*
	 * Get bits from bitstrings
	 */
	private static void fillBits(BitSet[] bits, String[] bitstrings) {
		for (int i = 0; i < BLOCK_SZ; ++i) {
			String bitstring = bitstrings[i];
			if (bitstring.length() != BLOCK_SZ) {
				int number = Integer.parseInt(bitstring);
				bitstring = Integer.toBinaryString(number);
			}
			bits[i] = fillBlock(bitstring);
		}
	}
	
	/*
	 * Get bits from bitstring
	 */
	private static BitSet fillBlock(String bitstring) {
		BitSet block = new BitSet(BLOCK_SZ);
		for (int i = 0; i < bitstring.length(); ++i) {
			if (bitstring.charAt(i) == BIT) {
				int index = BLOCK_SZ - bitstring.length() + i;
				block.set(index);
			}
		}
		return block;
	}
	
	/*
	 * Encryption
	 */
	private BitSet[][][] encrypt() {
		BitSet[][][] ciphertexts = new BitSet[plaintexts.length]
											 [keys.length]
											 [BLOCK_SZ];
		for (int i = 0; i < plaintexts.length; ++i) {
			for (int j = 0; j < keys.length; ++j) {
				ciphertexts[i][j] = encrypt(plaintexts[i], keys[j]);
			}
		}
		return ciphertexts;
	}
	
	/*
	 * Encryption
	 */
	protected BitSet[] encrypt(BitSet[] plaintext, BitSet[] key) {
		BitSet[] ciphertext = new BitSet[BLOCK_SZ];
		xorBlocks(plaintext, key);
		ciphertext[0] = sub(plaintext[1], 0);
		ciphertext[1] = sub(plaintext[3], 1);
		ciphertext[2] = sub(plaintext[0], 0);
		ciphertext[3] = sub(plaintext[2], 1);
		xorBlocks(plaintext, key);
		return ciphertext;
	}
	
	/*
	 * Block xor scheme
	 */
	protected static void xorBlocks(BitSet[] plaintext, BitSet[] key) {
		plaintext[0].xor(key[1]);
		plaintext[1].xor(key[0]);
		plaintext[2].xor(key[3]);
		plaintext[3].xor(key[2]);
	}
	
	/*
	 * Substitution box
	 */
	protected BitSet sub(BitSet xorBlock, int boxNo) {
		int row = toNum(xorBlock, 2, 3),
			col = toNum(xorBlock, 0, 1);
		return sboxes[boxNo][row][col];
	}
	
	/*
	 * Binary to int
	 */
	private static int toNum(BitSet xorBlock, int i, int j) {
		int num = 0;
		num += xorBlock.get(i) ? 2 : 0;
		num += xorBlock.get(j) ? 1 : 0;
		return num;
	}
	
	/*
	 * Prints each plaintext encrypted with each key
	 */
	private static void writeCiphertextPerKey(BitSet[][] ciphertextPerKey, PrintWriter writer, int textNo) {
		for (int i = 0; i < ciphertextPerKey.length; ++i) {
			writeCiphertext(ciphertextPerKey[i], writer, textNo, i + 1);
		}
	}
	
	/*
	 * Prints ciphertext
	 */
	private static void writeCiphertext(BitSet[] ciphertext, PrintWriter writer, int textNo, int keyNo) {
		writer.printf(OUTPUT, textNo, keyNo, textNo, keyNo);
		for (int i = 0; i < BLOCK_SZ; ++i) {
			writeBlock(ciphertext[i], writer);
		}
		writer.print('\t');
	}
	
	/*
	 * Prints ciphertext block
	 */
	private static void writeBlock(BitSet block, PrintWriter writer) {
		for (int i = 0; i < BLOCK_SZ; ++i) {
			char bit = block.get(i) ? BIT : NO_BIT;
			writer.print(bit);
		}
		writer.print(' ');
	}
	
	/*
	 * Write avalanche effect to the file
	 */
	protected void writeAvalancheEffect(PrintWriter writer) {
		int differentBits = 0;
		for (BitSet[] key : keys) {
			for (BitSet[] plaintext : plaintexts) {
				BitSet[] ciphertext = encrypt(plaintext, key);
				differentBits += differentBits(plaintext, key, ciphertext);
			}
		}
		double avalanche = differentBits / CHANGED_BITS;
		writer.printf(AVALANCHE, differentBits, avalanche);
	}
	
	/*
	 * Return number of bits changed in ciphertext (avalanche effect)
	 * for each inverted bit in the key
	 */
	protected int differentBits(BitSet[] plaintext, BitSet[] key, BitSet[] ciphertext) {
		int differentBits = 0;
		for (BitSet keyBlock : key) {
			for (int i = 0; i < BLOCK_SZ; ++i) {
				keyBlock.flip(i);
				BitSet[] newCiphertext = encrypt(plaintext, key);
				differentBits += differentCiphertextBits(ciphertext, newCiphertext);
				keyBlock.flip(i);
			}
		}
		return differentBits;
	}
	
	/*
	 * Return number of different bits between ciphertexts
	 */
	private static int differentCiphertextBits(BitSet[] ciphertext, BitSet[] newCiphertext) {
		int differentBits = 0;
		for (int i = 0; i < BLOCK_SZ; ++i) {
			differentBits += differentBlockBits(ciphertext[i], newCiphertext[i]);
		}
		return differentBits;
	}
	
	/*
	 * Return number of different bits between blocks
	 */
	private static int differentBlockBits(BitSet ciphertextBlock, BitSet newBlock) {
		int differentBits = 0;
		for (int i = 0; i < BLOCK_SZ; ++i) {
			if (ciphertextBlock.get(i) != newBlock.get(i)) {
				++differentBits;
			}
		}
		return differentBits;
	}
}








