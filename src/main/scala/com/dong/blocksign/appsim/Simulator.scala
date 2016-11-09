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

import io.ipfs.api._
import java.nio.file._

object Simulator extends App {
  var step = 0

  step += 1
  println(s"\n\n($step) ==================================================")
  println("SIMULATE TWO USERS: userA and userB")

  case class UserPub(accessPubKey: String, signPubKey: String) {
    def withEncryptedGuardKey(encryptedGuardKey: Array[Byte]) =
      UserPubWithEncryptedGuardKey(accessPubKey, signPubKey, encryptedGuardKey)
  }

  case class UserPubWithEncryptedGuardKey(accessPubKey: String, signPubKey: String, encryptedGuardKey: Array[Byte])

  case class User(
    accessPubKey: String,
    accessPrivKey: String,
    signPubKey: String,
    signPrivKey: String) {

    def accessECKey = ECKey.fromPrivate(Hex.decode(accessPrivKey))
    def signECKey = ECKey.fromPrivate(Hex.decode(signPrivKey))

    def getPub = UserPub(accessPubKey, signPubKey)

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

  case class DocToSign(
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
      s"\tfileContent:${fileContent}\n\tfileHash:${Hex.toHexString(fileHash)}" +
        s"\n\tguardKey(AES): ${Hex.toHexString(guardKey)}\n\tencryptedContent: ${encryptedContent}"
  }

  val filein = Paths.get("/Users/d/Desktop/b.pdf")

  val doc = DocToSign(Files.readAllBytes(filein))
  println("DocToSign:\n" + doc)

  val ipfs = new Client("localhost")

  val fileout = Paths.get("/tmp/" + Hex.toHexString(doc.fileHash))
  println("temp file for encrypted content: " + fileout)
  Files.write(fileout, doc.encryptedContent, StandardOpenOption.CREATE)
  val ipfsHash = ipfs.add(Array(fileout))(0).Hash
  println("ipfs hash: " + ipfsHash)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("ENCRYPT GUARD_KEY FOR BOTH USERS")

  val guardKeyforUserA = ECIESCoder.encrypt(userA.accessECKey.getPubKeyPoint, doc.guardKey)
  println("guardKeyforUserA: " + Hex.toHexString(guardKeyforUserA))

  val guardKeyforUserB = ECIESCoder.encrypt(userB.accessECKey.getPubKeyPoint, doc.guardKey)
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
      cipher.doFinal(doc.encryptedContent)
    }

    val hash = HashUtil.sha3(contentDecrypted)

    val same = Hex.toHexString(hash) == Hex.toHexString(doc.fileHash)
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
  println("GENERATE SIGNTASK")

  case class SignTask(
    fileHash: Array[Byte],
    encryptedContent: Array[Byte],
    signers: Seq[UserPubWithEncryptedGuardKey],
    ipfsHash: Option[String] = None,
    originatorNeedsToSign: Boolean = false) {

    def isValid() = signers.nonEmpty

    def getOriginator = signers.head
  }

  val signTask = SignTask(
    doc.fileHash,
    doc.encryptedContent,
    Seq(
      userA.getPub.withEncryptedGuardKey(guardKeyforUserA),
      userB.getPub.withEncryptedGuardKey(guardKeyforUserB)),
    Some(ipfsHash))

  println("signTask: " + signTask)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("SIGN THE FILE")

  println("UserA -------------")
  val sigA = userA.signECKey.doSign(signTask.fileHash)
  val userSigA = UserSig(userA.signPubKey, sigA.toBase64())
  println(userSigA)

  println("UserB -------------")
  val sigB = userB.signECKey.doSign(signTask.fileHash)
  val userSigB = UserSig(userB.signPubKey, sigB.toBase64())
  println(userSigB)

  case class UserSig(signPubKey: String, sig: String)

  case class SignTaskComplete(
    fileHash: String,
    signatures: Seq[UserSig]) {
    def verify(): Boolean = {
      signatures.map { userSig =>
        val key = ECKey.fromPublicOnly(Hex.decode(userSig.signPubKey))
        val bytes: Array[Byte] = Base64.decode(userSig.sig.getBytes("UTF-8"))
        val v = bytes(0)
        val r = bytes.slice(1, 33)
        val s = bytes.slice(33, 65)
        val sig = ECDSASignature.fromComponents(r, s, v)
        key.verify(Hex.decode(fileHash), sig)
      }.reduce(_ && _)
    }
  }

  val stc = SignTaskComplete(Hex.toHexString(signTask.fileHash), Seq(userSigA, userSigB))
  println("SignTaskComplete: " + stc)

  //
  //
  //

  step += 1
  println(s"\n\n($step) ==================================================")
  println("VERIFY SIGNATURE")

  println("Signatures verified?: " + stc.verify())

}

