lazy val root = (project in file(".")).
  settings(
    name := "hello",
    version := "1.0",
    scalaVersion := "2.11.8",
    libraryDependencies ++= Seq( // "org.apache.derby" % "derby" % "10.4.1.3",
      //"org.specs" % "specs" % "1.6.1"
      "io.ipfs" %% "scala-ipfs-api" % "1.0.0-SNAPSHOT"),
    resolvers ++= Seq(
      "scala-ipfs-api" at "https://ipfs.io/ipfs/QmbWUQEuTtFwNNg94nbpVY25b5PAyPQTd7HhkDsGhRG8Ur/",
      "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots"))