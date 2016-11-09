lazy val root = (project in file(".")).
  settings(
    name := "hello",
    version := "1.0",
    scalaVersion := "2.11.8",
    libraryDependencies ++= Seq( // "org.apache.derby" % "derby" % "10.4.1.3",
      //"org.specs" % "specs" % "1.6.1"
      // "com.madgag.spongycastle" % "pg" % "1.54.0.0",
      // "com.madgag.spongycastle" % "pkix" % "1.54.0.0",
      // "com.madgag.spongycastle" % "prov" % "1.54.0.0",
      "org.bouncycastle" % "bcprov-jdk15on" % "1.55",
      "org.bouncycastle" % "bcprov-ext-jdk15on" % "1.55",
      "org.bouncycastle" % "bcpkix-jdk15on" % "1.55",
      "io.ipfs" %% "scala-ipfs-api" % "1.0.0-SNAPSHOT",
      "com.itextpdf" % "itextpdf" % "5.5.6",
      "org.ethereum" % "ethereumj-core" % "1.3.6-RELEASE"),
    resolvers ++= Seq(
      // "scala-ipfs-api" at "https://ipfs.io/ipfs/QmbWUQEuTtFwNNg94nbpVY25b5PAyPQTd7HhkDsGhRG8Ur/",
      "Repository from Bintray" at "http://dl.bintray.com/ethereum/maven",
      "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"))