package org.example;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bitcoinj.core.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

public class BTCAddressGenerator {

    private BTCAddressGenerator() {}

    // prefix for P2SH testnet: this indicates the type of locking script to create (P2PKH, P2SH, etc)
    private static final String P2SH_TESTNET_PREFIX = "c4";
    // opcode for the number 2
    private static final String OP2 = "52";
    // opcode for the number 3
    private static final String OP3 = "53";
    // opcode for check multisig
    private static final String CHECK_MULTISIG = "ae";

    /**
     * Generates a P2SH 2 of 3 signature BTC address
     *
     * @return a P2SH testnet address
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static String generateP2SHMultiSig() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        // Create an ECDSA key pair and derive 3 public keys
        BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey1 = Sign.publicKeyFromPrivate(privateKey);
        BigInteger pubKey2 = Sign.publicKeyFromPrivate(privateKey);
        BigInteger pubKey3 = Sign.publicKeyFromPrivate(privateKey);

        // Compress the public keys
        String compressedPubKey1 = compressPubKey(pubKey1);
        String compressedPubKey2 = compressPubKey(pubKey2);
        String compressedPubKey3 = compressPubKey(pubKey3);

        // Build P2MS 2 of 3 Redeem Script
        // <OP_2> <pubkey_A> <pubkey_B> <pubkey_C> <OP_3> <OP_CHECKMULTISIG>
        String redeemScript = OP2 + compressedPubKey1 + compressedPubKey2 + compressedPubKey3 + OP3 + CHECK_MULTISIG;

        // Hash160 of the Redeem Script (SHA-256(RIPEMD160(redeemScript)))
        String hash160RedeemScript = bytesToHex(Hash.sha256hash160(Hex.decode(redeemScript)));

        // build checksum: error checking for the address
        // it is the first 4 bytes of SHA256(SHA256(prefix + redeem script hash))
        byte[] hashedData = Hash.sha256(Hash.sha256(hexStringToByteArray(P2SH_TESTNET_PREFIX + hash160RedeemScript)));
        String checksum = bytesToHex(hashedData).substring(0,8);

        // Base58 encode the address (prefix + redeem script hash + checksum)
        String address = P2SH_TESTNET_PREFIX + hash160RedeemScript + checksum;
        return Base58.encode(hexStringToByteArray(address));
    }

    /**
     * Generates a P2PKH BTC address
     *
     * @return a P2PKH testnet address
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static String generateP2PKH() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        // Create an ECDSA key pair and derive a public key
        BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privateKey);

        // Compress the public key
        String compressedPubKey = compressPubKey(pubKey);

        // Hash160 of the Public Key (SHA-256(RIPEMD160(compressedPubKey)))
        String hash160PublicKey = bytesToHex(Hash.sha256hash160(Hex.decode(compressedPubKey)));

        // build checksum: error checking for the address
        // it is the first 4 bytes of SHA256(SHA256(prefix + redeem script hash))
        byte[] hashedData = Hash.sha256(Hash.sha256(hexStringToByteArray("6f" + hash160PublicKey)));
        String checksum = bytesToHex(hashedData).substring(0,8);

        // Base58 encode the address (prefix + pubkey hash + checksum)
        String address = "6f" + hash160PublicKey + checksum;
        return Base58.encode(hexStringToByteArray(address));
    }

    private static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    private static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();

        for (byte hashInByte : hashInBytes) {
            sb.append(Integer.toString((hashInByte & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        byte[] b = new byte[s.length() / 2];

        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }

        return b;
    }
}
