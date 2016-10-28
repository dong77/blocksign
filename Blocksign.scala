package com.dong.blocksign

import java.math.BigInteger
import java.security._

class ECDSASigner {

  def genKey() = {
    val keyGen = KeyPairGenerator.getInstance("EC")
    val random = SecureRandom.getInstance("SHA1PRNG")

    keyGen.initialize(256, random)

    keyGen.generateKeyPair()

  }
  def sign(pair: KeyPair, content: String) = {
    // val pub = pair.getPublic()

    val dsa = Signature.getInstance("SHA1withECDSA")
    dsa.initSign(pair.getPrivate())

    val strByte = content.getBytes("UTF-8")
    dsa.update(strByte)

    dsa.sign()
  }
}

object blocksign {
  def main(args: Array[String]) {
    val signer = new ECDSASigner()
    val pair = signer.genKey()
    val sig = signer.sign(pair, "hui")
    println("Signature: " + new BigInteger(1, sig).toString(16))

  }
}