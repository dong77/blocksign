package com.dong.blocksign.appsim

import java.util.Properties
import java.io._
import java.security._
import java.security.cert.Certificate
import com.itextpdf.text._
import com.itextpdf.text.pdf._
import com.itextpdf.text.pdf.security._
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.ethereum.crypto._
import java.nio.file._

class Signatures {

  val properties = new Properties()
  properties.load(this.getClass.getResourceAsStream("/key.properties"))

  def createPdf(filename: String) {
    val document = new Document()
    PdfWriter.getInstance(document, new FileOutputStream(filename))
    document.open()
    document.add(new Paragraph("Hello World!"))
    document.close()
  }

  def signPdfFirstTime(src: String, dest: String, version: String, rect: Rectangle) {
    val priv = properties.getProperty("PRIVATE")
    val password = properties.getProperty("PASSWORD")

    val ks = KeyStore.getInstance("PKCS12", "BC")
    val privateResource = this.getClass().getResourceAsStream(priv)
    ks.load(privateResource, password.toCharArray())

    val alias: String = ks.aliases().nextElement()
    val pk = ks.getKey(alias, password.toCharArray()).asInstanceOf[PrivateKey]
    val chain = ks.getCertificateChain(alias)
    // reader and stamper
    val reader = new PdfReader(src)
    val os = new FileOutputStream(dest)
    val stamper = PdfStamper.createSignature(reader, os, '\0', new File("/tmp"), true)
    // appearance
    val appearance = stamper.getSignatureAppearance()

    appearance.setImage(Image.getInstance(properties.getProperty("IMAGE")))
    appearance.setReason("This is signed by block-sign")
    appearance.setLocation("Foobar")
    appearance.setVisibleSignature(rect, 1, version)
    // digital signature
    val es = new PrivateKeySignature(pk, "SHA-256", "BC")
    val digest = new BouncyCastleDigest()
    MakeSignature.signDetached(appearance, digest, es, chain,
      null, null, null, 0, MakeSignature.CryptoStandard.CMS)
  }

  def manipulatePdf(src: String, dest: String) {
    val reader = new PdfReader(src)
    val stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true)
    val info = reader.getInfo()
    info.put("Title", "Hello World stamped")
    info.put("Subject", "Hello World with changed metadata")
    info.put("Keywords", "iText in Action, PdfStamper")
    info.put("Creator", "Silly standalone example")
    info.put("Author", "Also Bruno Lowagie")
    stamper.setMoreInfo(info)
    stamper.close()
    reader.close()
  }
  /*

      public void verifySignatures() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        //FileInputStream is1 = new FileInputStream(properties.getProperty("ROOTCERT"));
        InputStream is1 = this.getClass().getResourceAsStream(properties.getProperty("ROOTCERT"));
        X509Certificate cert1 = (X509Certificate) cf.generateCertificate(is1);
        ks.setCertificateEntry("cacert", cert1);
        InputStream is2 = this.getClass().getResourceAsStream("/ia.crt");
        X509Certificate cert2 = (X509Certificate) cf.generateCertificate(is2);
        ks.setCertificateEntry("foobar", cert2);

        PrintWriter out = new PrintWriter(new FileOutputStream(VERIFICATION));
        PdfReader reader = new PdfReader(SIGNED2);
        AcroFields af = reader.getAcroFields();
        ArrayList<String> names = af.getSignatureNames();
        for (String name : names) {
            out.println("Signature name: " + name);
            out.println("Signature covers whole document: " + af.signatureCoversWholeDocument(name));
            out.println("Document revision: " + af.getRevision(name) + " of " + af.getTotalRevisions());
            PdfPKCS7 pk = af.verifySignature(name);
            Calendar cal = pk.getSignDate();
            Certificate[] pkc = pk.getCertificates();
            out.println("Subject: " + CertificateInfo.getSubjectFields(pk.getSigningCertificate()));
            out.println("Revision modified: " + !pk.verify());
            List<VerificationException> errors = CertificateVerification.verifyCertificates(pkc, ks, null, cal);
            if (errors.size() == 0)
                out.println("Certificates verified against the KeyStore");
            else
                out.println(errors);
        }
        out.flush();
        out.close();
    }

    */

  def extractRevision(src: String, dest: String, version: String) {
    val reader = new PdfReader(src)
    val af = reader.getAcroFields()
    val os = new FileOutputStream(dest)
    val bb = new Array[Byte](1028)
    val ip = af.extractRevision(version)
    var n = ip.read(bb)
    while (n > 0) {
      os.write(bb, 0, n)
      n = ip.read(bb)
    }
    os.close()
    ip.close()
  }

  def compareFiles(f1: String, f2: String) = {
    val hash1 = HashUtil.sha3(Files.readAllBytes(Paths.get(f1)))
    val hash2 = HashUtil.sha3(Files.readAllBytes(Paths.get(f2)))
    hash1 == hash2
  }

}

object Signatures extends App {
  val ORIGINAL = "results/hello.pdf"
  val SIGNED1 = "results/signature_1.pdf"
  val SIGNED1_MODIFIED = "results/signature_1_modified.pdf"
  val SIGNED2 = "results/signature_2.pdf"
  val RESTORED1 = "results/restored_1.pdf"
  val VERIFICATION = "results/verify.txt"
  Security.insertProviderAt(new BouncyCastleProvider(), 1)

  val signatures = new Signatures()
  signatures.createPdf(ORIGINAL)
  signatures.signPdfFirstTime(ORIGINAL, SIGNED1, "Sign1", new Rectangle(0, 100, 200, 200)) // llx,lly,urx,ury
  signatures.manipulatePdf(SIGNED1, SIGNED1_MODIFIED)
  signatures.signPdfFirstTime(SIGNED1_MODIFIED, SIGNED2, "Sign2", new Rectangle(400, 100, 600, 200))

  signatures.extractRevision(SIGNED1, RESTORED1, "Sign1")

  val same = signatures.compareFiles(ORIGINAL, RESTORED1)
  println("Same? " + same)
}
