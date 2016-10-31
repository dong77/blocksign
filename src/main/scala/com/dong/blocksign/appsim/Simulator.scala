package com.dong.blocksign.appsim

import java.security._
import java.security.spec._
import javax.crypto._
import javax.crypto.spec._
import java.math.BigInteger
import org.spongycastle.util.encoders._
import org.ethereum.util.ByteUtil.bigIntegerToBytes
import org.ethereum.crypto.ECKey._
import org.ethereum.crypto.jce._
import org.ethereum.crypto._

object Simulator extends App {

  // val pair = KeyUtil.generateECDSAKeyPair()

  // println(pair.getPublic.getEncoded.size)
  // println(pair.getPrivate.getEncoded.size)
  // val privKey = new BigInteger(Hex.toHexString(pair.getPublic.getEncoded), 16)
  // val pubKey = new BigInteger(Hex.toHexString(pair.getPrivate.getEncoded), 16)

  println("\n\n==================================================")
  println("SIMULATE TWO USERS: userA and userB")

  case class User(
    accessPubKey: String,
    accessPrivKey: String,
    signPubKey: String,
    signPrivKey: String) {

    def accessECKey = ECKey.fromPrivate(Hex.decode(accessPrivKey))
    def signECKey = ECKey.fromPrivate(Hex.decode(signPrivKey))

    override def toString() = s"\taccessPubKey: $accessPubKey\n\taccessPrivKey: $accessPrivKey\n\tsignPubKey: $signPubKey\n\tsignPrivKey: $signPrivKey"
  }

  val userA = {
    val accessKey = new ECKey
    val signKey = new ECKey
    User(
      Hex.toHexString(accessKey.getPubKey),
      Hex.toHexString(accessKey.getPrivKeyBytes),
      Hex.toHexString(signKey.getPubKey),
      Hex.toHexString(signKey.getPrivKeyBytes))
  }

  println("UserA:\n" + userA); println("-" * 40)

  val userB = {
    val accessKey = new ECKey
    val signKey = new ECKey
    User(
      Hex.toHexString(accessKey.getPubKey),
      Hex.toHexString(accessKey.getPrivKeyBytes),
      Hex.toHexString(signKey.getPubKey),
      Hex.toHexString(signKey.getPrivKeyBytes))
  }

  println("UserB:\n" + userB); println("-" * 40)

  val users = Seq(userA, userB)

  println("\n\n==================================================")
  println("CREATE A NEW SIGN TASK")

  case class SignTask(
    fileContent: Array[Byte]) {

    lazy val fileHash = HashUtil.sha3(fileContent)
    lazy val guardKey = {
      val kgen = KeyGenerator.getInstance("AES")
      kgen.init(128)
      val key = kgen.generateKey()
      key.getEncoded()
    }

    lazy val encryptedContent = {
      val cipher = Cipher.getInstance("AES")
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(guardKey, "AES"))
      cipher.doFinal(fileContent)
    }

    override def toString() =
      s"\tfileContent:${Hex.toHexString(fileContent)}\n\tfileHash:${Hex.toHexString(fileHash)}" +
        s"\n\tguardKey(AES): ${Hex.toHexString(guardKey)}\n\tencryptedContent: ${Hex.toHexString(encryptedContent)}"
  }

  val fileContent = ("abc" * 10).getBytes

  val task = SignTask(fileContent)
  println("task:\n" + task)

  println("==================================================")
  println("ENCRYPT GUARD_KEY FOR BOTH USERS")

  val guardKeyforUserA = ECIESCoder.encrypt(userA.accessECKey.getPubKeyPoint, task.guardKey)
  println("guardKeyforUserA: " + Hex.toHexString(guardKeyforUserA))

  val guardKeyforUserB = ECIESCoder.encrypt(userB.accessECKey.getPubKeyPoint, task.guardKey)
  println("guardKeyforUserB: " + Hex.toHexString(guardKeyforUserB))

  case class Assignment(user: User, encryptedGuardKey: Array[Byte]) {
    override def toString() = user.toString + s"\n\tencryptedGuardKey: ${Hex.toHexString(encryptedGuardKey)}"
  }

  val assignmentA = Assignment(userA, guardKeyforUserA)
  val assignmentB = Assignment(userB, guardKeyforUserB)
  println("assignmentA:\n" + assignmentA); println("-" * 40)
  println("assignmentB:\n" + assignmentB); println("-" * 40)

  println("==================================================")
  println("UserA DECRYPTE AND CHECK THE FILE (works the same for userB)")

  val guardKeyDecryptedByUserA = ECIESCoder.decrypt(userA.accessECKey.getPrivKey, guardKeyforUserA)
  println("guardKeyDecryptedByUserA: " + Hex.toHexString(guardKeyDecryptedByUserA))

  val contentDecryptedByUserA = {
    val cipher = Cipher.getInstance("AES")
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(guardKeyDecryptedByUserA, "AES"));
    cipher.doFinal(task.encryptedContent)
  }

  println(s"contentDecryptedByUserA: ${Hex.toHexString(contentDecryptedByUserA)}")
  val hash = HashUtil.sha3(fileContent)

  val same = Hex.toHexString(hash) == Hex.toHexString(task.fileHash)
  println(s"file decrypted by A is the same as the original: $same")

  println("==================================================")
  println("UserA SIGN THE FILE (works the same for userB)")

  val sigA = userA.signECKey.doSign(task.fileHash)
  val sigABase64 = sigA.toBase64()
  println("sigABase64: " + sigABase64)

  println("==================================================")
  println("VERIFY userA's SIGNATURE (works the same for userB)")

  println("userA's sig is valid?: " + userA.signECKey.verify(task.fileHash, sigA))
}