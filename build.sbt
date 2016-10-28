lazy val root = (project in file(".")).
  settings(
    name := "hello",
    version := "1.0",
    scalaVersion := "2.11.8",
    libraryDependencies ++= Seq(
      "org.apache.derby" % "derby" % "10.4.1.3",
      "org.specs" % "specs" % "1.6.1"),
    resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots")