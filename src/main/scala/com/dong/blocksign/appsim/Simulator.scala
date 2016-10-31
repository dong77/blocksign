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
  var step = 0

  step += 1
  println(s"\n\n($step) ==================================================")
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

  println("UserA -------------")
  println(userA)

  val userB = {
    val accessKey = new ECKey
    val signKey = new ECKey
    User(
      Hex.toHexString(accessKey.getPubKey),
      Hex.toHexString(accessKey.getPrivKeyBytes),
      Hex.toHexString(signKey.getPubKey),
      Hex.toHexString(signKey.getPrivKeyBytes))
  }
  println("UserB -------------")
  println(userB)

  val users = Seq(userA, userB)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
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

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
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

  println("assignmentA -------------")
  println(assignmentA)

  println("assignmentB -------------")
  println(assignmentB)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("DECRYPTE AND CHECK THE FILE")

  def decode(user: User, encryptedGuardKey: Array[Byte]) = {
    val guardKeyDecrypted = ECIESCoder.decrypt(user.accessECKey.getPrivKey, encryptedGuardKey)
    println("guardKeyDecrypted: " + Hex.toHexString(guardKeyDecrypted))

    val contentDecrypted = {
      val cipher = Cipher.getInstance("AES")
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(guardKeyDecrypted, "AES"));
      cipher.doFinal(task.encryptedContent)
    }

    println(s"contentDecrypted: ${Hex.toHexString(contentDecrypted)}")
    val hash = HashUtil.sha3(contentDecrypted)

    val same = Hex.toHexString(hash) == Hex.toHexString(task.fileHash)
    println(s"file decrypted by A is the same as the original: $same")
  }

  println("UserA -------------")
  decode(userA, guardKeyforUserA)

  println("UserB -------------")
  decode(userB, guardKeyforUserB)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("SIGN THE FILE")

  def signDoc(user: User) = {
    val sig = user.signECKey.doSign(task.fileHash)
    println("sigBase64: " + sig.toBase64())
    sig
  }

  println("UserA -------------")
  val sigA = signDoc(userA)

  println("UserB -------------")
  val sigB = signDoc(userB)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("VERIFY SIGNATURE")

  println("userA's sig is valid?: " + userA.signECKey.verify(task.fileHash, sigA))
  println("userB's sig is valid?: " + userB.signECKey.verify(task.fileHash, sigB))
}

