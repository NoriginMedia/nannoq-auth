pipeline {
  agent any
  
  triggers {
    pollSCM('')
    githubPush()
  }
  
  options {
    buildDiscarder(logRotator(numToKeepStr: '1'))
    disableConcurrentBuilds()
    timeout(time: 1, unit: 'HOURS')
    retry(3)
  }
  
  tools {
    jdk "jdk8"
    maven "maven"
  }
  
  stages {
    stage("Build Nannoq-Auth") {
      steps {
        configFileProvider([configFile(fileId: 'ossrh-nannoq-config', variable: 'MAVEN_SETTINGS')]) {
          sh 'mvn -s $MAVEN_SETTINGS clean deploy'
        }
      }
    }
  }
  
  post {
    failure {
      mail to: 'mikkelsen.anders@gmail.com',
          subject: "Failed Pipeline: ${currentBuild.fullDisplayName}",
          body: "Something is wrong with ${env.BUILD_URL}"
    }
  }
}
