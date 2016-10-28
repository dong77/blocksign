package com.dong.blocksign

import java.math.BigInteger
import java.security._
import javax.crypto._
import javax.crypto.spec._
import fr.acinq.bitcoin.Base58
import io.ipfs.api.Client
import java.nio.file._
import java.util
import io.ipfs.api.Add

class Encryptor {
  def makeKey(): SecretKeySpec = {
    val kgen = KeyGenerator.getInstance("AES")
    kgen.init(128)
    val key = kgen.generateKey()
    val aesKey = key.getEncoded()
    new SecretKeySpec(aesKey, "AES")
  }

  def encrypt(aeskeySpec: SecretKeySpec, input: String): Array[Byte] = {

    val cipher = Cipher.getInstance("AES")
    cipher.init(Cipher.ENCRYPT_MODE, aeskeySpec)
    cipher.doFinal(input.getBytes("UTF-8"))
  }

  def decrypt(aeskeySpec: SecretKeySpec, input: Array[Byte]): Array[Byte] = {
    val cipher = Cipher.getInstance("AES")
    cipher.init(Cipher.DECRYPT_MODE, aeskeySpec);
    cipher.doFinal(input)
  }
}

class ECDSASigner {

  def genKey() = {
    val keyGen = KeyPairGenerator.getInstance("EC")
    val random = SecureRandom.getInstance("SHA1PRNG")

    keyGen.initialize(256, random)

    keyGen.generateKeyPair()

  }
  def sign(pair: KeyPair, input: String): Array[Byte] = {
    // val pub = pair.getPublic()

    val dsa = Signature.getInstance("SHA1withECDSA")
    dsa.initSign(pair.getPrivate())

    val strByte = input.getBytes("UTF-8")
    dsa.update(strByte)
    dsa.sign()
  }
}

class FileManager(ipfs: String = "localhost") {
  val client = new Client(ipfs)

  def store(str: String): String = store(str.getBytes("UTF-8"))

  def store(bytes: Array[Byte]): String = {
    val path = Paths.get("fdaf")
    Files.write(path, bytes, StandardOpenOption.CREATE)
    client.add(Array(path))(0).Hash
  }
}

object Main {
  def main(args: Array[String]) {
    val signer = new ECDSASigner()
    val encryptor = new Encryptor()
    val pair = signer.genKey()
    val aesKey = encryptor.makeKey()

    val input = "hello world"
    println("input: " + input)
    val encrypted = encryptor.encrypt(aesKey, input)
    println("encrypted: " + Base58.encode(encrypted))

    val decrypted = encryptor.decrypt(aesKey, encrypted)
    println("decrypted: " + new String(decrypted))

    val sig = signer.sign(pair, "hui")
    println("Signature: " + Base58.encode(sig))

    val manager = new FileManager()
    val hash = manager.store("fdasfafas")
    println(hash)

  }
}